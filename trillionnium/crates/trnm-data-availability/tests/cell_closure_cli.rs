//! The supported binary, real argv and real TCP bytes; no model/install claim.
#![cfg(unix)]

use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use trnm_data_availability::cell::{
    digest_hex, serve_cells, CellCacheConfigV4, CellManifestV1, CellPeerLimitsV1,
    CellReleaseClosureV1, CellStoreV1, MAX_CELL_CLOSURE_BYTES_V1,
};

struct ChildOwner(Option<Child>);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn cli(args: &[String]) -> Output {
    let child = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut owner = ChildOwner(Some(child));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if owner.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            return owner.0.take().unwrap().wait_with_output().unwrap();
        }
        assert!(Instant::now() < deadline, "CLI child deadline");
        thread::sleep(Duration::from_millis(5));
    }
}

fn cache_config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: 64 * 1024 * 1024,
        max_chunk_rows: 4096,
        max_manifest_rows: 256,
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    origin_path: PathBuf,
    closure_path: PathBuf,
    closure: CellReleaseClosureV1,
    response_bytes: u64,
}
impl Fixture {
    fn new() -> Self {
        let data: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../formal/pon-nakamoto-v1/vectors/cell-dependency-closure-v1.json"
        )))
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let origin_path = directory.path().join("origin.sqlite");
        let store = CellStoreV1::open(&origin_path, cache_config()).unwrap();
        let mut response_bytes = 0;
        for value in data["manifests"].as_array().unwrap() {
            let wire = hex::decode(value["wire_hex"].as_str().unwrap()).unwrap();
            let payload = hex::decode(value["payload_hex"].as_str().unwrap()).unwrap();
            let manifest = CellManifestV1::decode(&wire).unwrap();
            store.put_manifest(manifest.id(), &wire).unwrap();
            store.put_chunk(&manifest.chunks()[0], &payload).unwrap();
            response_bytes += wire.len() as u64 + payload.len() as u64 + 18;
        }
        let wire = hex::decode(data["wire_hex"].as_str().unwrap()).unwrap();
        let closure = CellReleaseClosureV1::decode(&wire).unwrap();
        let closure_path = directory.path().join("owner.tcd1");
        fs::write(&closure_path, wire).unwrap();
        Self {
            directory,
            origin_path,
            closure_path,
            closure,
            response_bytes,
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }
    fn args(&self, cache: &str, output: &str, peer: &str) -> Vec<String> {
        let context = self.closure.release().context();
        let mut args = vec!["fetch-closure".to_owned()];
        for (key, value) in [
            ("--authentication-profile", "content-cache-v1".to_owned()),
            ("--cache-max-bytes", "67108864".into()),
            ("--cache-max-chunks", "4096".into()),
            ("--cache-max-manifests", "256".into()),
            ("--cache-max-db-bytes", "134217728".into()),
            ("--store", self.path(cache).display().to_string()),
            ("--closure-file", self.closure_path.display().to_string()),
            ("--closure", digest_hex(self.closure.id())),
            (
                "--loader-generation",
                self.closure.selected_generation().to_string(),
            ),
            (
                "--loader-profile",
                digest_hex(self.closure.loader_profile()),
            ),
            ("--required-roles", "base,tokenizer".into()),
            ("--family", context.family.clone()),
            ("--base", digest_hex(context.base)),
            ("--parent", digest_hex(context.parent)),
            ("--tokenizer", digest_hex(context.tokenizer)),
            ("--layout", digest_hex(context.layout)),
            ("--runtime", digest_hex(context.runtime)),
            ("--peers", peer.into()),
            ("--output", self.path(output).display().to_string()),
            (
                "--max-bytes",
                self.closure
                    .files()
                    .iter()
                    .map(|file| file.payload_bytes)
                    .sum::<u64>()
                    .to_string(),
            ),
            ("--max-chunks", "3".into()),
            ("--overall-ms", "5000".into()),
            ("--request-ms", "500".into()),
            ("--parallelism", "1".into()),
            ("--max-connections", "6".into()),
            ("--max-response-bytes", self.response_bytes.to_string()),
        ] {
            args.push(key.into());
            args.push(value);
        }
        args
    }
}

fn replace(args: &mut [String], key: &str, value: String) {
    let index = args.iter().position(|argument| argument == key).unwrap();
    args[index + 1] = value;
}

struct Peer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<u64>>,
}
impl Peer {
    fn new(path: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let child_stop = stop.clone();
        let path = path.to_owned();
        let handle = thread::spawn(move || {
            let store = CellStoreV1::open(&path, cache_config()).unwrap();
            serve_cells(
                &listener,
                &store,
                &child_stop,
                CellPeerLimitsV1 {
                    request_timeout: Duration::from_millis(500),
                    overall_timeout: Duration::from_secs(30),
                    max_cell_bytes: 1_048_576,
                    parallelism: 1,
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

#[test]
fn cli_rejects_owner_context_and_authentication_downgrade_before_cache_or_dial() {
    let fixture = Fixture::new();
    let peer = Peer::new(&fixture.origin_path);
    for (index, (key, value)) in [
        ("--closure", digest_hex([9; 32])),
        ("--loader-generation", "8".into()),
        ("--loader-profile", digest_hex([9; 32])),
        ("--runtime", digest_hex([9; 32])),
        ("--required-roles", "adapter".into()),
        ("--required-roles", "base,base".into()),
        ("--authentication-profile", "cell-pq-v999".into()),
    ]
    .into_iter()
    .enumerate()
    {
        let cache = format!("wrong-{index}.sqlite");
        let marker = format!("wrong-{index}.tcd");
        let mut args = fixture.args(&cache, &marker, &peer.address.to_string());
        replace(&mut args, key, value);
        let output = cli(&args);
        assert!(!output.status.success(), "{key}");
        assert!(output.stdout.is_empty());
        assert!(!fixture.path(&cache).exists() && !fixture.path(&marker).exists());
    }
    let mut args = fixture.args(
        "missing-profile.sqlite",
        "missing-profile.tcd",
        &peer.address.to_string(),
    );
    let index = args
        .iter()
        .position(|arg| arg == "--authentication-profile")
        .unwrap();
    args.drain(index..index + 2);
    let output = cli(&args);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("explicit authentication profile"));
    assert!(!fixture.path("missing-profile.sqlite").exists());
    assert_eq!(peer.finish(), 0);
}

#[test]
fn cli_fetches_real_bytes_shares_budget_resumes_and_never_overwrites_marker() {
    let fixture = Fixture::new();
    let peer = Peer::new(&fixture.origin_path);
    let address = peer.address.to_string();
    let accepted = cli(&fixture.args("cache.sqlite", "complete.tcd", &address));
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(report["schema"], "trnm.cell.closure.fetch.v1");
    assert_eq!(report["closure"], digest_hex(fixture.closure.id()));
    assert_eq!(report["generation"], 7);
    assert_eq!(report["cells"], 3);
    assert_eq!(report["downloaded_chunks"], 3);
    assert_eq!(report["connection_attempts"], 6);
    assert_eq!(report["received_response_bytes"], fixture.response_bytes);
    assert_eq!(report["selection_authority"], false);
    assert_eq!(report["use_authority"], false);
    assert_eq!(
        fs::read(fixture.path("complete.tcd")).unwrap(),
        fixture.closure.encode()
    );
    let mut short_args = fixture.args("short.sqlite", "short.tcd", &address);
    replace(&mut short_args, "--max-connections", "5".into());
    let short = cli(&short_args);
    assert!(!short.status.success());
    assert!(!fixture.path("short.tcd").exists());
    let resumed = cli(&fixture.args("short.sqlite", "short.tcd", &address));
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&resumed.stdout).unwrap();
    assert_eq!(report["cached_chunks"], 2);
    assert_eq!(report["downloaded_chunks"], 1);
    assert_eq!(report["connection_attempts"], 1);
    let mut cached_args = fixture.args("cache.sqlite", "cache-only.tcd", "");
    replace(&mut cached_args, "--max-response-bytes", "0".into());
    let cached = cli(&cached_args);
    assert!(
        cached.status.success(),
        "{}",
        String::from_utf8_lossy(&cached.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&cached.stdout).unwrap();
    assert_eq!(report["cached_chunks"], 3);
    assert_eq!(report["connection_attempts"], 0);
    let before = fs::read(fixture.path("cache-only.tcd")).unwrap();
    let existing = cli(&cached_args);
    assert!(!existing.status.success());
    assert!(String::from_utf8_lossy(&existing.stderr).contains("release marker exists"));
    assert_eq!(fs::read(fixture.path("cache-only.tcd")).unwrap(), before);
    assert_eq!(peer.finish(), 12);
}

#[test]
fn cli_bounds_input_descriptor_and_rejects_symlink_directory_and_wrong_wire() {
    let fixture = Fixture::new();
    let alias = fixture.path("alias.tcd");
    std::os::unix::fs::symlink(&fixture.closure_path, &alias).unwrap();
    let oversized = fixture.path("oversized.tcd");
    fs::write(&oversized, vec![0; MAX_CELL_CLOSURE_BYTES_V1 + 1]).unwrap();
    let suffix = fixture.path("suffix.tcd");
    let mut wrong = fixture.closure.encode();
    wrong.push(0);
    fs::write(&suffix, wrong).unwrap();
    for (index, path) in [
        alias,
        fixture.directory.path().to_owned(),
        oversized,
        suffix,
    ]
    .into_iter()
    .enumerate()
    {
        let cache = format!("input-{index}.sqlite");
        let marker = format!("input-{index}.tcd");
        let mut args = fixture.args(&cache, &marker, "");
        replace(&mut args, "--closure-file", path.display().to_string());
        let output = cli(&args);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!fixture.path(&cache).exists() && !fixture.path(&marker).exists());
    }
}
