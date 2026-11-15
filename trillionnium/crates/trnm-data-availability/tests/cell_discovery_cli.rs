//! Actual opt-in CLI processes and bounded transport, not independent operators.
//! Advertisements, downloaded bytes and these fixtures confer no model authority.

#![cfg(unix)]

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use trnm_data_availability::cell::{
    digest_hex,
    discovery::{cell_discovery_context_digest, CellProviderRecordV1},
    serve_cells, CellContextV1, CellManifestV1, CellPeerLimitsV1, CellStoreV1,
};

const PROFILE: &str = "cell-provider-discovery-dev-v1";
// A reproducible, explicitly synthetic test seed; no host or user key is read.
const SECRET: [u8; 32] = [b'K'; 32];
const LOG_LIMIT: u64 = 16_384;

struct ChildOwner(Option<Child>);

impl ChildOwner {
    fn completed(&mut self) -> Child {
        // This is test-process cleanup, not a renewal of the command's fixed
        // 10s protocol deadline or evidence of a paid resource reservation.
        let end = Instant::now() + Duration::from_secs(15);
        loop {
            if self.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                return self.0.take().unwrap();
            }
            assert!(
                Instant::now() < end,
                "bounded discovery CLI child did not terminate"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for ChildOwner {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn cli(args: &[String]) -> Output {
    let child = Command::new(env!("CARGO_BIN_EXE_trnm-cell-discovery"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut owner = ChildOwner(Some(child));
    owner.completed().wait_with_output().unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|part| part == needle)
}

fn no_secret(output: &Output, secret: &[u8]) {
    let lower_hex = hex::encode(secret);
    let upper_hex = lower_hex.to_uppercase();
    let decimal = format!("{secret:?}");
    for channel in [&output.stdout, &output.stderr] {
        for representation in [
            secret,
            lower_hex.as_bytes(),
            upper_hex.as_bytes(),
            decimal.as_bytes(),
        ] {
            assert!(
                !contains(channel, representation),
                "CLI leaked synthetic private key material"
            );
        }
    }
}

fn json_success(args: &[String]) -> Value {
    let output = cli(args);
    no_secret(&output, &SECRET);
    // Do not interpolate captured stdout/stderr into assertion failures, even
    // if a future broken implementation prints a differently encoded secret.
    assert!(
        output.status.success(),
        "CLI operation {} failed: {}",
        args[0],
        output.status
    );
    serde_json::from_slice(&output.stdout).expect("CLI success must be one JSON record")
}

fn command(name: &str) -> Vec<String> {
    vec![name.into(), "--profile".into(), PROFILE.into()]
}

fn arg(args: &mut Vec<String>, name: &str, value: impl Into<String>) {
    args.push(name.into());
    args.push(value.into());
}

fn path_arg(args: &mut Vec<String>, name: &str, path: &Path) {
    arg(args, name, path.display().to_string());
}

fn common(args: &mut Vec<String>) {
    for (name, byte) in [
        ("--namespace", 1),
        ("--network", 2),
        ("--parameters", 3),
        ("--genesis", 4),
    ] {
        arg(args, name, digest_hex([byte; 32]));
    }
}

fn replace(args: &mut [String], name: &str, value: impl Into<String>) {
    let index = args.iter().position(|item| item == name).unwrap();
    args[index + 1] = value.into();
}

fn scope(args: &mut Vec<String>, peers: &[SocketAddr]) {
    let mut ports: Vec<_> = peers.iter().map(SocketAddr::port).collect();
    ports.sort_unstable();
    ports.dedup();
    arg(args, "--scope", "loopback-dev");
    arg(
        args,
        "--ports",
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
    );
}

fn client_limits(args: &mut Vec<String>) {
    for (key, value) in [
        ("--overall-ms", "10000"),
        ("--request-ms", "2000"),
        ("--max-bytes", "1048576"),
        ("--parallelism", "2"),
        ("--max-connections", "64"),
        ("--max-response-bytes", "4194304"),
    ] {
        arg(args, key, value);
    }
}

fn private_file(path: &Path, contents: &[u8], mode: u32) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(contents).unwrap();
    file.sync_all().unwrap();
    // Explicit final mode makes the public-mode negative independent of umask.
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn cell_context() -> CellContextV1 {
    CellContextV1 {
        family: "pn5-cli-transport-fixture-v1".into(),
        base: [11; 32],
        parent: [12; 32],
        tokenizer: [13; 32],
        layout: [14; 32],
        runtime: [15; 32],
    }
}

fn material(path: &Path) -> (CellManifestV1, Vec<u8>, PathBuf) {
    let bytes: Vec<_> = (0_u32..1025)
        .flat_map(|value| <[u8; 32]>::from(Sha256::digest(value.to_be_bytes())))
        .collect();
    let input = path.join("actual-input");
    fs::write(&input, &bytes).unwrap();
    let source = path.join("source.sqlite");
    let store = CellStoreV1::open(&source, cache_config()).unwrap();
    let manifest = store.pack_file(&input, cell_context(), 16_384).unwrap();
    (manifest, bytes, source)
}

struct Peer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<u64>>,
}

impl Peer {
    fn start(path: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let path = path.to_owned();
        let handle = thread::spawn(move || {
            let store = CellStoreV1::open(&path, cache_config()).unwrap();
            serve_cells(
                &listener,
                &store,
                &stopped,
                CellPeerLimitsV1 {
                    request_timeout: Duration::from_secs(2),
                    overall_timeout: Duration::from_secs(30),
                    max_cell_bytes: 1_048_576,
                    parallelism: 2,
                    max_connections: 64,
                    max_response_bytes: 0,
                },
            )
            .unwrap()
        });
        Self {
            address,
            stop,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn bounded_file(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(LOG_LIMIT + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(
        bytes.len() <= LOG_LIMIT as usize,
        "bounded CLI log exceeded fixture limit"
    );
    bytes
}

struct RendezvousChild {
    address: SocketAddr,
    child: ChildOwner,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl RendezvousChild {
    fn start(path: &Path, providers: &[SocketAddr], max_connections: u64) -> Self {
        let directory = path.join("rendezvous.sqlite");
        let mut init = command("init");
        path_arg(&mut init, "--directory", &directory);
        common(&mut init);
        json_success(&init);
        assert!(directory.is_file());
        let mut args = command("serve");
        path_arg(&mut args, "--directory", &directory);
        common(&mut args);
        scope(&mut args, providers);
        arg(&mut args, "--bind", "127.0.0.1:0");
        arg(&mut args, "--seconds", "20");
        arg(&mut args, "--request-ms", "2000");
        arg(&mut args, "--max-connections", max_connections.to_string());
        let stdout = path.join("rendezvous.stdout");
        let stderr = path.join("rendezvous.stderr");
        let out_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stdout)
            .unwrap();
        let err_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stderr)
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_trnm-cell-discovery"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out_file))
            .stderr(Stdio::from(err_file))
            .spawn()
            .unwrap();
        let mut owner = ChildOwner(Some(child));
        let end = Instant::now() + Duration::from_secs(10);
        let address = loop {
            let bytes = bounded_file(&stdout);
            if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
                let report: Value = serde_json::from_slice(&bytes[..end]).unwrap();
                assert_eq!(report["schema"], "trnm.cell.discovery.listen.v1");
                break report["address"]
                    .as_str()
                    .unwrap()
                    .parse::<SocketAddr>()
                    .unwrap();
            }
            assert!(
                owner.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "rendezvous exited before its listen record"
            );
            assert!(Instant::now() < end, "rendezvous readiness deadline");
            thread::sleep(Duration::from_millis(5));
        };
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        Self {
            address,
            child: owner,
            stdout,
            stderr,
        }
    }

    fn finish(mut self) {
        let status = self.child.completed().wait().unwrap();
        assert!(
            status.success(),
            "rendezvous must exit naturally after its exact connection budget"
        );
        bounded_file(&self.stdout);
        bounded_file(&self.stderr);
    }
}

struct SignedFixture {
    record: PathBuf,
    owner: String,
    cell_context: String,
}

fn sign_fixture(path: &Path, manifest: &CellManifestV1, endpoint: SocketAddr) -> SignedFixture {
    let secret = path.join("synthetic-private-key");
    private_file(&secret, &SECRET, 0o600);
    let mut key_args = command("key-public");
    path_arg(&mut key_args, "--secret-key-file", &secret);
    let public = json_success(&key_args);
    let owner = public["owner"].as_str().unwrap().to_owned();
    assert_eq!(
        owner,
        digest_hex(SigningKey::from_bytes(&SECRET).verifying_key().to_bytes())
    );
    let mut context_args = command("context-digest");
    let context = cell_context();
    arg(&mut context_args, "--family", context.family.clone());
    for (name, digest) in [
        ("--base", context.base),
        ("--parent", context.parent),
        ("--tokenizer", context.tokenizer),
        ("--layout", context.layout),
        ("--runtime", context.runtime),
    ] {
        arg(&mut context_args, name, digest_hex(digest));
    }
    let report = json_success(&context_args);
    let context_digest = report["cell_context"].as_str().unwrap().to_owned();
    assert_eq!(
        context_digest,
        digest_hex(cell_discovery_context_digest(&context).unwrap())
    );
    let record = path.join("signed-provider.cdp1");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut sign = command("sign");
    common(&mut sign);
    path_arg(&mut sign, "--record-output", &record);
    path_arg(&mut sign, "--secret-key-file", &secret);
    arg(&mut sign, "--owner", owner.clone());
    arg(&mut sign, "--manifest", digest_hex(manifest.id()));
    arg(&mut sign, "--cell-context", context_digest.clone());
    arg(&mut sign, "--endpoint", endpoint.to_string());
    arg(&mut sign, "--sequence", "1");
    arg(&mut sign, "--issued-unix-seconds", now.to_string());
    arg(&mut sign, "--expires-unix-seconds", (now + 300).to_string());
    let signed = json_success(&sign);
    let wire = fs::read(&record).unwrap();
    assert_eq!(signed["record_bytes"], 335);
    assert_eq!(wire.len(), 335);
    assert_eq!(
        signed["record_sha256"],
        digest_hex(Sha256::digest(&wire).into())
    );
    let decoded = CellProviderRecordV1::decode(&wire).unwrap();
    assert_eq!(decoded.statement().endpoint, endpoint);
    assert_eq!(decoded.statement().request.manifest, manifest.id());
    // A second sign may not overwrite a complete record, even with equal input.
    let duplicate = cli(&sign);
    no_secret(&duplicate, &SECRET);
    assert!(!duplicate.status.success());
    assert_eq!(fs::read(&record).unwrap(), wire);
    SignedFixture {
        record,
        owner,
        cell_context: context_digest,
    }
}

fn announce_args(
    signed: &SignedFixture,
    manifest: &CellManifestV1,
    bootstrap: SocketAddr,
    provider: SocketAddr,
) -> Vec<String> {
    let mut args = command("announce");
    common(&mut args);
    path_arg(&mut args, "--record", &signed.record);
    arg(&mut args, "--owner", signed.owner.clone());
    arg(&mut args, "--manifest", digest_hex(manifest.id()));
    arg(&mut args, "--cell-context", signed.cell_context.clone());
    arg(&mut args, "--bootstrap", bootstrap.to_string());
    scope(&mut args, &[bootstrap, provider]);
    client_limits(&mut args);
    args
}

fn fetch_args(
    path: &Path,
    manifest: &CellManifestV1,
    context: &str,
    bootstrap: SocketAddr,
    provider: SocketAddr,
) -> Vec<String> {
    let mut args = command("fetch");
    common(&mut args);
    path_arg(
        &mut args,
        "--directory",
        &path.join("consumer-directory.sqlite"),
    );
    path_arg(&mut args, "--store", &path.join("consumer-cache.sqlite"));
    arg(&mut args, "--cache-max-bytes", "67108864");
    arg(&mut args, "--cache-max-chunks", "4096");
    arg(&mut args, "--cache-max-manifests", "256");
    arg(&mut args, "--cache-max-db-bytes", "134217728");
    arg(&mut args, "--manifest", digest_hex(manifest.id()));
    arg(&mut args, "--cell-context", context);
    // This is the only selection list: the actual provider is learned from TCP.
    arg(&mut args, "--bootstraps", bootstrap.to_string());
    scope(&mut args, &[bootstrap, provider]);
    client_limits(&mut args);
    path_arg(&mut args, "--output", &path.join("downloaded-cell"));
    args
}

#[test]
fn cli_bootstrap_only_fetch_uses_real_signed_records_and_exact_shared_response_budget() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest, bytes, source) = material(temp.path());
    let provider = Peer::start(&source);
    let provider_address = provider.address;
    let signed = sign_fixture(temp.path(), &manifest, provider_address);
    // One announce plus one discovery lookup: the CLI server must naturally
    // finish after these exact two connections, without a teardown kill.
    let rendezvous = RendezvousChild::start(temp.path(), &[provider_address], 2);
    json_success(&announce_args(
        &signed,
        &manifest,
        rendezvous.address,
        provider_address,
    ));
    let args = fetch_args(
        temp.path(),
        &manifest,
        &signed.cell_context,
        rendezvous.address,
        provider_address,
    );
    assert!(!args.iter().any(|arg| arg == "--peers"));
    let fetched = json_success(&args);
    rendezvous.finish();
    let expected_connections = 2 + manifest.chunks().len() as u64;
    let expected_bytes = 345
        + 9
        + manifest.encode().len() as u64
        + bytes.len() as u64
        + 9 * manifest.chunks().len() as u64;
    assert_eq!(fetched["manifest"], digest_hex(manifest.id()));
    assert_eq!(
        fetched["payload_sha256"],
        digest_hex(Sha256::digest(&bytes).into())
    );
    assert_eq!(fetched["manifest_initial_cache_hit"], false);
    assert_eq!(fetched["connection_attempts"], expected_connections);
    assert_eq!(fetched["received_response_bytes"], expected_bytes);
    assert_eq!(fetched["discovery"]["connection_attempts"], 1);
    assert_eq!(fetched["discovery"]["received_response_bytes"], 345);
    assert_eq!(fetched["discovery"]["record_validation_attempts"], 1);
    assert_eq!(
        fetched["suppliers"],
        serde_json::json!([provider_address.to_string()])
    );
    let output = fs::read(temp.path().join("downloaded-cell")).unwrap();
    assert_eq!(output, bytes);
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&output)),
        manifest.payload_sha256()
    );
    assert_eq!(provider.finish(), 1 + manifest.chunks().len() as u64);
}

#[test]
fn cli_requires_explicit_profile_and_rejects_unknown_or_duplicate_arguments_before_init() {
    let temp = tempfile::tempdir().unwrap();
    for case in ["missing-profile", "wrong-profile", "duplicate", "unknown"] {
        let directory = temp.path().join(case);
        let mut args = command("init");
        common(&mut args);
        path_arg(&mut args, "--directory", &directory);
        match case {
            "missing-profile" => {
                drop(args.drain(1..3));
            }
            "wrong-profile" => replace(&mut args, "--profile", "permissionless-production"),
            "duplicate" => arg(&mut args, "--profile", PROFILE),
            "unknown" => arg(&mut args, "--unknown", "value"),
            _ => unreachable!(),
        }
        let failed = cli(&args);
        no_secret(&failed, &SECRET);
        assert!(
            !failed.status.success(),
            "invalid init admission case: {case}"
        );
        assert!(
            !directory.exists(),
            "invalid admission must not create a discovery namespace: {case}"
        );
    }
}

#[test]
fn cli_private_key_length_permissions_and_symlink_fail_without_secret_output() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("valid-target");
    private_file(&target, &SECRET, 0o600);
    let symlink_path = temp.path().join("symlink-key");
    symlink(&target, &symlink_path).unwrap();
    let short = temp.path().join("short-key");
    let long = temp.path().join("long-key");
    let public = temp.path().join("public-key-file");
    private_file(&short, &[b'K'; 31], 0o600);
    private_file(&long, &[b'K'; 33], 0o600);
    private_file(&public, &SECRET, 0o644);
    for (path, contents) in [
        (&short, vec![b'K'; 31]),
        (&long, vec![b'K'; 33]),
        (&public, SECRET.to_vec()),
        (&symlink_path, SECRET.to_vec()),
    ] {
        let mut args = command("key-public");
        path_arg(&mut args, "--secret-key-file", path);
        let failed = cli(&args);
        no_secret(&failed, &contents);
        assert!(
            !failed.status.success(),
            "invalid private-key file must be rejected"
        );
    }
    assert_eq!(fs::read(&target).unwrap(), SECRET);
}

#[test]
fn cli_rejects_record_pin_mismatch_and_mutated_records_before_bootstrap_dial() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest, _bytes, _source) = material(temp.path());
    let provider = TcpListener::bind("127.0.0.1:0").unwrap();
    let provider_address = provider.local_addr().unwrap();
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let bootstrap = trap.local_addr().unwrap();
    let signed = sign_fixture(temp.path(), &manifest, provider_address);
    for flag in ["--owner", "--manifest", "--cell-context", "--namespace"] {
        let mut args = announce_args(&signed, &manifest, bootstrap, provider_address);
        replace(&mut args, flag, digest_hex([99; 32]));
        let failed = cli(&args);
        no_secret(&failed, &SECRET);
        assert!(
            !failed.status.success(),
            "record pin must reject before transport: {flag}"
        );
        assert!(
            matches!(trap.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
    let original = fs::read(&signed.record).unwrap();
    for (label, bytes) in [
        ("extra-byte", {
            let mut bytes = original.clone();
            bytes.push(0);
            bytes
        }),
        ("changed-signature", {
            let mut bytes = original.clone();
            bytes[334] ^= 1;
            bytes
        }),
    ] {
        let changed = temp.path().join(label);
        fs::write(&changed, bytes).unwrap();
        let mut args = announce_args(&signed, &manifest, bootstrap, provider_address);
        replace(&mut args, "--record", changed.display().to_string());
        let failed = cli(&args);
        no_secret(&failed, &SECRET);
        assert!(
            !failed.status.success(),
            "invalid signed record must reject: {label}"
        );
        assert!(
            matches!(trap.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
    assert_eq!(fs::read(&signed.record).unwrap(), original);
}

#[test]
fn cli_wrong_cell_context_cannot_discover_provider_or_publish_payload() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest, _bytes, source) = material(temp.path());
    let provider = Peer::start(&source);
    let provider_address = provider.address;
    let signed = sign_fixture(temp.path(), &manifest, provider_address);
    // A real accepted announce and both original bounded lookup rounds.
    let rendezvous = RendezvousChild::start(temp.path(), &[provider_address], 3);
    json_success(&announce_args(
        &signed,
        &manifest,
        rendezvous.address,
        provider_address,
    ));
    let args = fetch_args(
        temp.path(),
        &manifest,
        &digest_hex([99; 32]),
        rendezvous.address,
        provider_address,
    );
    let failed = cli(&args);
    no_secret(&failed, &SECRET);
    assert!(!failed.status.success());
    assert!(!temp.path().join("downloaded-cell").exists());
    rendezvous.finish();
    assert_eq!(
        provider.finish(),
        0,
        "a mismatching pinned Cell context may not select or dial the advertised provider"
    );
}

// Explicit finite fixture quota; covers the existing <=32MiB commit fixtures.
fn cache_config() -> trnm_data_availability::cell::CellCacheConfigV4 {
    trnm_data_availability::cell::CellCacheConfigV4 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: 64 * 1024 * 1024,
        max_chunk_rows: 4096,
        max_manifest_rows: 256,
    }
}
