//! Actual opt-in CLI capture, held-descriptor refusals, and post-join failure facts.
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use trnm_crypto_primitives::{public_key_hex, signing_key_from_hex};
use trnm_pon_node::{development_public, ingress, Node, PoolLimits, Settings};

struct Fixture {
    root: PathBuf,
    _temporary: Option<tempfile::TempDir>,
    genesis: u64,
    settings: Settings,
    public: String,
}
impl Fixture {
    fn new(name: &str) -> Self {
        let (root, temporary) =
            match std::env::var_os("PUBLIC_REQUEST_OBSERVATION_CLI_EVIDENCE_DIR") {
                Some(parent) => {
                    let root = PathBuf::from(parent).join(name);
                    fs::create_dir(&root).unwrap();
                    (root, None)
                }
                None => {
                    let temporary = tempfile::tempdir().unwrap();
                    (temporary.path().to_owned(), Some(temporary))
                }
            };
        let genesis = ingress::now().unwrap() - 100;
        let settings = Settings::development(Some(genesis)).unwrap();
        // Fresh local test directory, public deterministic DEV-only identities.
        // These files are never read from an operator's business key directory.
        let key = |name: &str, byte: u8| {
            let secret = hex::encode([byte; 32]);
            let path = root.join(name);
            fs::write(&path, &secret).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            public_key_hex(&signing_key_from_hex(&secret).unwrap())
        };
        let public = key("server.dev-key", 113);
        key("guest.dev-key", 114);
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
        Self {
            root,
            _temporary: temporary,
            genesis,
            settings,
            public,
        }
    }
    fn command(&self, operation: &str, label: &str) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
        c.arg(operation)
            .args(["--development", "--genesis-time", &self.genesis.to_string()]);
        c.arg("--store")
            .arg(self.root.join(format!("{label}.store")));
        c
    }
    fn service(
        &self,
        label: &str,
        capture: bool,
        capacity: Option<u64>,
        broken_stdout: bool,
    ) -> Service {
        let mut c = self.command("serve", label);
        c.args([
            "--admission-profile",
            ingress::public_v3::PROFILE,
            "--public-development-network",
            "--listen",
            "127.0.0.1:0",
            "--seconds",
            "4",
            "--admission-bits",
            "8",
        ])
        .arg("--pool-policy")
        .arg(self.root.join("pool.json"))
        .arg("--auth-secret")
        .arg(self.root.join("server.dev-key"));
        if capture {
            c.arg("--request-observation-output")
                .arg(self.root.join(format!("{label}.json")));
        }
        if let Some(capacity) = capacity {
            c.args(["--request-observation-capacity", &capacity.to_string()]);
        }
        if broken_stdout {
            c.args(["--mine", "--blocks", "3", "--pace-ms", "1000"]);
        }
        Service::start(c, &self.root, label, broken_stdout)
    }
    fn head(&self, service: &Service, label: &str) -> Output {
        let mut c = self.command("head", label);
        c.args([
            "--admission-profile",
            ingress::public_v3::PROFILE,
            "--peer",
            service.ready["address"].as_str().unwrap(),
            "--server-public",
            &self.public,
            "--admission-bits",
            "8",
        ])
        .arg("--auth-secret")
        .arg(self.root.join("guest.dev-key"));
        run(c, &self.root, label)
    }
    fn observation(&self, label: &str) -> Value {
        serde_json::from_slice(&fs::read(self.root.join(format!("{label}.json"))).unwrap()).unwrap()
    }
}

fn record_command(command: &Command, root: &Path, label: &str) {
    let argv: Vec<_> = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    fs::write(
        root.join(format!("{label}.argv.json")),
        serde_json::to_vec(&argv).unwrap(),
    )
    .unwrap();
}
fn record_output(output: &Output, root: &Path, label: &str, elapsed: Duration) {
    fs::write(root.join(format!("{label}.stdout")), &output.stdout).unwrap();
    fs::write(root.join(format!("{label}.stderr")), &output.stderr).unwrap();
    fs::write(root.join(format!("{label}.wait.json")), serde_json::to_vec(&json!({
        "actual_parent_wait":true,"returncode":output.status.code(),"signal":output.status.signal(),
        "elapsed_ns":elapsed.as_nanos(),"scope":"local test child, not CPU or deadline/SLA"
    })).unwrap()).unwrap();
}
fn read_all(mut stream: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        bytes
    })
}
fn wait(child: &mut Child, deadline: Instant) -> std::process::ExitStatus {
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let status = child.wait().unwrap();
            panic!("finite local CLI child budget exhausted, actual wait={status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
fn run(mut command: Command, root: &Path, label: &str) -> Output {
    record_command(&command, root, label);
    let started = Instant::now();
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = read_all(child.stdout.take().unwrap());
    let stderr = read_all(child.stderr.take().unwrap());
    let status = wait(&mut child, started + Duration::from_secs(12));
    let output = Output {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    };
    record_output(&output, root, label, started.elapsed());
    output
}
struct Service {
    child: Child,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
    ready: Value,
    root: PathBuf,
    label: String,
    started: Instant,
}
impl Service {
    fn start(mut command: Command, root: &Path, label: &str, close_stdout: bool) -> Self {
        record_command(&command, root, label);
        let started = Instant::now();
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = Some(read_all(child.stderr.take().unwrap()));
        let mut pipe = BufReader::new(child.stdout.take().unwrap());
        let (tx, rx) = mpsc::channel();
        let stdout = Some(thread::spawn(move || {
            let mut first = String::new();
            pipe.read_line(&mut first).unwrap();
            tx.send(first.clone()).unwrap();
            let mut bytes = first.into_bytes();
            if !close_stdout {
                pipe.read_to_end(&mut bytes).unwrap();
            }
            bytes
        }));
        let first = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let ready: Value = serde_json::from_str(&first).unwrap();
        assert_eq!(ready["event"], "listening");
        Self {
            child,
            stdout,
            stderr,
            ready,
            root: root.to_owned(),
            label: label.into(),
            started,
        }
    }
    fn finish(&mut self) -> Output {
        let status = wait(&mut self.child, self.started + Duration::from_secs(15));
        let output = Output {
            status,
            stdout: self.stdout.take().unwrap().join().unwrap(),
            stderr: self.stderr.take().unwrap().join().unwrap(),
        };
        record_output(&output, &self.root, &self.label, self.started.elapsed());
        output
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
        }
        self.child.wait().unwrap();
        if let Some(stdout) = self.stdout.take() {
            stdout.join().unwrap();
        }
        if let Some(stderr) = self.stderr.take() {
            stderr.join().unwrap();
        }
    }
}
fn assert_success(out: &Output) {
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn actual_opt_in_capture_and_default_output_keep_the_same_public_context() {
    let f = Fixture::new("normal");
    let mut default = f.service("default", false, None, false);
    assert_success(&f.head(&default, "default-head"));
    let default_out = default.finish();
    assert_success(&default_out);
    assert!(!f.root.join("default.json").exists());
    let mut observed = f.service("observed", true, None, false);
    assert_eq!(observed.ready["state"], default.ready["state"]);
    assert_eq!(
        observed.ready["admission_profile_digest"],
        default.ready["admission_profile_digest"]
    );
    assert_eq!(
        observed.ready["pool_context"],
        default.ready["pool_context"]
    );
    assert_eq!(fs::metadata(f.root.join("observed.json")).unwrap().len(), 0);
    assert_success(&f.head(&observed, "observed-head"));
    assert_success(&observed.finish());
    let v = f.observation("observed");
    assert_eq!(v["schema"], "public-v3-local-cli-request-observation-v1");
    assert_eq!(v["context"]["network"], hex::encode(f.settings.network()));
    assert_eq!(
        v["context"]["parameters"],
        hex::encode(f.settings.parameters())
    );
    assert_eq!(v["context"]["genesis"], hex::encode(f.settings.genesis()));
    assert_eq!(
        v["context"]["admission_policy_id"],
        observed.ready["admission_profile_digest"]
    );
    assert_eq!(v["source_claim"]["commit"], Value::Null);
    assert_eq!(v["source_claim"]["tree"], Value::Null);
    assert_eq!(v["completion"]["service_succeeded"], true);
    assert_eq!(v["completion"]["all_scoped_workers_joined"], true);
    assert_eq!(v["completion"]["capture_coverage_complete"], true);
    assert_eq!(v["snapshot"]["capacity"], 1024);
    assert_eq!(v["snapshot"]["accepted_connections_seen"], 1);
    let row = &v["snapshot"]["records"][0];
    assert_eq!(row["complete"], true);
    assert_eq!(row["physical_network_bytes"], Value::Null);
    assert_eq!(row["full_work_thread_cpu_ns"], Value::Null);
    assert_eq!(row["full_work_started"], false);
    assert_eq!(v["public_network_ready"], false);
    assert_eq!(v["model_quality_qualified"], false);
    let bytes = fs::read(f.root.join("observed.json")).unwrap();
    assert!(bytes.len() <= 16 * 1024 * 1024);
    let text = String::from_utf8(bytes).unwrap();
    for private in [
        f.root.to_str().unwrap(),
        observed.ready["address"].as_str().unwrap(),
        f.public.as_str(),
    ] {
        assert!(
            !text.contains(private),
            "local locator/identity must not be exported"
        );
    }
    assert_eq!(
        fs::metadata(f.root.join("observed.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let final_line = String::from_utf8(default_out.stdout).unwrap();
    let final_value: Value = serde_json::from_str(final_line.lines().last().unwrap()).unwrap();
    assert_eq!(
        final_value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        [
            "mining",
            "peer_polling",
            "production_activation",
            "public_network_ready",
            "result"
        ]
    );
}

#[test]
fn retention_loss_is_explicit_and_pre_join_kill_does_not_publish_completion() {
    let f = Fixture::new("partial");
    let mut service = f.service("capacity-one", true, Some(1), false);
    assert_success(&f.head(&service, "head-one"));
    assert_success(&f.head(&service, "head-two"));
    assert_success(&service.finish());
    let v = f.observation("capacity-one");
    assert_eq!(v["snapshot"]["records"].as_array().unwrap().len(), 1);
    assert_eq!(v["snapshot"]["accepted_connections_seen"], 2);
    assert_eq!(v["snapshot"]["records_not_retained"], 1);
    assert_eq!(v["completion"]["capture_coverage_complete"], false);
    let mut killed = f.service("killed", true, None, false);
    killed.child.kill().unwrap();
    let out = killed.finish();
    assert_eq!(out.status.signal(), Some(libc::SIGKILL));
    let bytes = fs::read(f.root.join("killed.json")).unwrap();
    assert!(bytes.is_empty());
    assert!(serde_json::from_slice::<Value>(&bytes).is_err());
}

#[test]
fn option_and_create_new_nofollow_refusals_precede_node_open() {
    let f = Fixture::new("refusals");
    let cases: &[(&str, &[&str], &str)] = &[
        (
            "capacity-alone",
            &[
                "--admission-profile",
                ingress::public_v3::PROFILE,
                "--public-development-network",
                "--request-observation-capacity",
                "1",
            ],
            "OUTPUT_REQUIRED",
        ),
        (
            "zero",
            &[
                "--admission-profile",
                ingress::public_v3::PROFILE,
                "--public-development-network",
                "--request-observation-capacity",
                "0",
            ],
            "PUBLIC_OBSERVATION_CAPACITY",
        ),
        (
            "too-many",
            &[
                "--admission-profile",
                ingress::public_v3::PROFILE,
                "--public-development-network",
                "--request-observation-capacity",
                "4097",
            ],
            "PUBLIC_OBSERVATION_CAPACITY",
        ),
        (
            "bad-capacity",
            &[
                "--admission-profile",
                ingress::public_v3::PROFILE,
                "--public-development-network",
                "--request-observation-capacity",
                "no",
            ],
            "invalid --request-observation-capacity",
        ),
        (
            "no-explicit",
            &["--admission-profile", ingress::public_v3::PROFILE],
            "EXPLICIT_PUBLIC_V3_REQUIRED",
        ),
        ("legacy", &[], "EXPLICIT_PUBLIC_V3_REQUIRED"),
        (
            "v2",
            &[
                "--admission-profile",
                ingress::public_v2::PROFILE,
                "--public-development-network",
            ],
            "EXPLICIT_PUBLIC_V3_REQUIRED",
        ),
    ];
    for (label, args, expected) in cases {
        let mut c = f.command("serve", label);
        c.args(*args);
        let output = f.root.join(format!("{label}.json"));
        if *label != "capacity-alone" {
            c.arg("--request-observation-output").arg(&output);
        }
        let out = run(c, &f.root, label);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains(expected));
        assert!(!f.root.join(format!("{label}.store")).exists());
        assert!(!output.exists());
    }
    let mut c = f.command("status", "other-command");
    c.arg("--request-observation-output")
        .arg(f.root.join("other.json"));
    let out = run(c, &f.root, "other-command");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("UNKNOWN_OPTION"));
    assert!(!f.root.join("other-command.store").exists());
    fs::write(f.root.join("existing"), b"original bytes").unwrap();
    fs::create_dir(f.root.join("directory")).unwrap();
    std::os::unix::fs::symlink(f.root.join("existing"), f.root.join("symlink")).unwrap();
    for name in ["existing", "directory", "symlink"] {
        let mut c = f.command("serve", name);
        c.args([
            "--admission-profile",
            ingress::public_v3::PROFILE,
            "--public-development-network",
        ])
        .arg("--request-observation-output")
        .arg(f.root.join(name));
        let out = run(c, &f.root, name);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("REQUEST_OBSERVATION_OUTPUT_FILE"));
        assert!(!f.root.join(format!("{name}.store")).exists());
    }
    assert_eq!(
        fs::read(f.root.join("existing")).unwrap(),
        b"original bytes"
    );
}

#[test]
fn post_join_output_failure_preserves_service_facts_and_native_store() {
    let f = Fixture::new("io-failure");
    let mut service = f.service("owner", true, None, false);
    fs::hard_link(f.root.join("owner.json"), f.root.join("added-link")).unwrap();
    assert_success(&f.head(&service, "honest-head"));
    let out = service.finish();
    assert_eq!(out.status.code(), Some(2));
    let error = String::from_utf8_lossy(&out.stderr);
    for fact in [
        "REQUEST_OBSERVATION_OUTPUT_IO",
        "all_scoped_workers_joined=true",
        "service_succeeded=true",
        "ledger_effects_not_rolled_back=true",
    ] {
        assert!(error.contains(fact));
    }
    assert!(!error.contains(f.root.to_str().unwrap()));
    assert_eq!(fs::metadata(f.root.join("owner.json")).unwrap().len(), 0);
    let node = Node::open(&f.root.join("owner.store"), f.settings.clone(), 1).unwrap();
    assert_eq!(node.active().unwrap().0, f.settings.genesis());
}

#[test]
fn joined_miner_failure_still_exports_facts_before_error_propagation() {
    let f = Fixture::new("miner-failure");
    let mut service = f.service("owner", true, None, true);
    // The test closes the stdout pipe after the initial listening row. A later
    // real miner callback fails to print; it does not erase committed blocks.
    let out = service.finish();
    assert_eq!(out.status.code(), Some(2));
    let v = f.observation("owner");
    assert_eq!(v["completion"]["all_scoped_workers_joined"], true);
    assert_eq!(v["completion"]["service_succeeded"], true);
    assert_eq!(v["completion"]["mining_succeeded"], false);
    assert_eq!(v["completion"]["peer_polling_succeeded"], Value::Null);
    let node = Node::open(&f.root.join("owner.store"), f.settings.clone(), 1).unwrap();
    assert!(node.stats().unwrap()["height"].as_u64().unwrap() >= 1);
}
