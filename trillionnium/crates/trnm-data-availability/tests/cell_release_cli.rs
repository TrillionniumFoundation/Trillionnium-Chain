//! Actual CLI admission, shared budgets and create-only marker checks.

use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use trnm_data_availability::cell::{
    digest_hex, serve_cells, CellContextV1, CellPeerLimitsV1, CellReleaseManifestV1, CellStoreV1,
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
            let store = CellStoreV1::open(&path).unwrap();
            serve_cells(
                &listener,
                &store,
                &child_stop,
                CellPeerLimitsV1 {
                    request_timeout: Duration::from_millis(500),
                    overall_timeout: Duration::from_secs(20),
                    max_cell_bytes: 1_048_576,
                    parallelism: 1,
                    max_connections: 32,
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

fn fetch_args(
    cache: &Path,
    root: &Path,
    pinned: &str,
    peer: &str,
    output: &Path,
    budget: u64,
) -> Vec<String> {
    [
        "fetch-release".into(),
        "--store".into(),
        cache.display().to_string(),
        "--release-file".into(),
        root.display().to_string(),
        "--release".into(),
        pinned.into(),
        "--peers".into(),
        peer.into(),
        "--output".into(),
        output.display().to_string(),
        "--max-bytes".into(),
        "42000".into(),
        "--max-chunks".into(),
        "4".into(),
        "--overall-ms".into(),
        "5000".into(),
        "--max-connections".into(),
        "6".into(),
        "--max-response-bytes".into(),
        budget.to_string(),
    ]
    .into()
}

#[test]
fn cli_pins_release_and_shares_budgets_before_create_only_completion() {
    let directory = tempfile::tempdir().unwrap();
    let origin_path = directory.path().join("origin.sqlite");
    let origin = CellStoreV1::open(&origin_path).unwrap();
    let context = CellContextV1 {
        family: "release-cli-v1".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    };
    let input = directory.path().join("input");
    fs::write(&input, vec![1; 20_000]).unwrap();
    let first = origin.pack_file(&input, context.clone(), 16_384).unwrap();
    fs::write(&input, vec![2; 22_000]).unwrap();
    let second = origin.pack_file(&input, context.clone(), 16_384).unwrap();
    let release = CellReleaseManifestV1::new(context, vec![first.id(), second.id()]).unwrap();
    let root = directory.path().join("owner.tcr1");
    let prepared = cli(&prepare_args(
        &origin_path,
        &format!("{},{}", digest_hex(second.id()), digest_hex(first.id())),
        &root,
        42_000,
        4,
    ));
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let prepared_report: serde_json::Value = serde_json::from_slice(&prepared.stdout).unwrap();
    assert_eq!(prepared_report["schema"], "trnm.cell.release.prepare.v1");
    assert_eq!(prepared_report["release"], digest_hex(release.id()));
    assert_eq!(prepared_report["payload_bytes"], 42_000);
    assert_eq!(prepared_report["chunks"], 4);
    assert_eq!(fs::read(&root).unwrap(), release.encode());
    let pinned = digest_hex(release.id());
    let budget = first.encode().len() as u64 + second.encode().len() as u64 + 42_000 + 6 * 9;
    let peer = Peer::new(&origin_path);
    let address = peer.address.to_string();
    let cache = directory.path().join("cache.sqlite");
    let marker = directory.path().join("complete.tcr1");

    let wrong_cache = directory.path().join("wrong.sqlite");
    let wrong = cli(&fetch_args(
        &wrong_cache,
        &root,
        &digest_hex([9; 32]),
        &address,
        &marker,
        budget,
    ));
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("release manifest digest"));
    assert!(!marker.exists() && !wrong_cache.exists());

    let accepted = cli(&fetch_args(
        &cache, &root, &pinned, &address, &marker, budget,
    ));
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(report["cells"], 2);
    assert_eq!(report["payload_bytes"], 42_000);
    assert_eq!(report["downloaded_chunks"], 4);
    assert_eq!(report["connection_attempts"], 6);
    assert_eq!(report["received_response_bytes"], budget);
    assert_eq!(fs::read(&marker).unwrap(), release.encode());

    let short_marker = directory.path().join("short.tcr1");
    let short = cli(&fetch_args(
        &directory.path().join("short.sqlite"),
        &root,
        &pinned,
        &address,
        &short_marker,
        budget - 1,
    ));
    assert!(!short.status.success());
    assert!(String::from_utf8_lossy(&short.stderr).contains("CELL_RESPONSE_BYTE_BUDGET_EXHAUSTED"));
    assert!(!short_marker.exists());

    let cache_marker = directory.path().join("cached.tcr1");
    let cached = cli(&fetch_args(&cache, &root, &pinned, "", &cache_marker, 0));
    assert!(cached.status.success());
    let report: serde_json::Value = serde_json::from_slice(&cached.stdout).unwrap();
    assert_eq!(report["received_response_bytes"], 0);
    assert_eq!(report["connection_attempts"], 0);
    assert_eq!(report["cached_chunks"], 4);
    assert_eq!(fs::read(cache_marker).unwrap(), release.encode());
    let existing = cli(&fetch_args(&cache, &root, &pinned, "", &marker, 0));
    assert!(!existing.status.success());
    assert!(String::from_utf8_lossy(&existing.stderr).contains("release marker exists"));
    assert_eq!(fs::read(&marker).unwrap(), release.encode());

    let verify = cli(&[
        "verify-release".into(),
        "--store".into(),
        cache.display().to_string(),
        "--release-file".into(),
        marker.display().to_string(),
        "--release".into(),
        pinned,
        "--max-bytes".into(),
        "42000".into(),
        "--max-chunks".into(),
        "4".into(),
        "--seconds".into(),
        "5".into(),
    ]);
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert_eq!(peer.finish(), 12);
}

fn prepare_args(
    store: &Path,
    members: &str,
    output: &Path,
    bytes: u64,
    chunks: u64,
) -> Vec<String> {
    [
        "prepare-release".into(),
        "--store".into(),
        store.display().to_string(),
        "--manifests".into(),
        members.into(),
        "--output".into(),
        output.display().to_string(),
        "--max-bytes".into(),
        bytes.to_string(),
        "--max-chunks".into(),
        chunks.to_string(),
        "--overall-ms".into(),
        "5000".into(),
    ]
    .into()
}

#[test]
fn cli_release_preparation_rejects_incomplete_incompatible_and_over_budget_sets() {
    let directory = tempfile::tempdir().unwrap();
    let origin_path = directory.path().join("origin.sqlite");
    let origin = CellStoreV1::open(&origin_path).unwrap();
    let context = CellContextV1 {
        family: "prepare-cli-v1".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    };
    let input = directory.path().join("input");
    fs::write(&input, vec![1; 20_000]).unwrap();
    let first = origin.pack_file(&input, context.clone(), 16_384).unwrap();
    fs::write(&input, vec![2; 22_000]).unwrap();
    let second = origin.pack_file(&input, context.clone(), 16_384).unwrap();
    let mut other_context = context.clone();
    other_context.parent = [7; 32];
    let other = origin.pack_file(&input, other_context, 16_384).unwrap();
    let exact = format!("{},{}", digest_hex(first.id()), digest_hex(second.id()));
    let cases = [
        (
            "duplicate",
            format!("{0},{0}", digest_hex(first.id())),
            42_000,
            4,
        ),
        (
            "missing",
            format!("{},{}", digest_hex(first.id()), digest_hex([9; 32])),
            42_000,
            4,
        ),
        (
            "incompatible",
            format!("{},{}", digest_hex(first.id()), digest_hex(other.id())),
            42_000,
            4,
        ),
        ("payload-budget", exact.clone(), 41_999, 4),
        ("chunk-budget", exact.clone(), 42_000, 3),
    ];
    for (name, members, bytes, chunks) in cases {
        let output = directory.path().join(format!("{name}.tcr1"));
        let result = cli(&prepare_args(
            &origin_path,
            &members,
            &output,
            bytes,
            chunks,
        ));
        assert!(!result.status.success(), "{name} unexpectedly prepared");
        assert!(!output.exists(), "{name} published an incomplete root");
    }
    let deadline_output = directory.path().join("deadline.tcr1");
    let mut ambiguous = prepare_args(&origin_path, &exact, &deadline_output, 42_000, 4);
    ambiguous.extend(["--seconds".into(), "5".into()]);
    assert!(!cli(&ambiguous).status.success());
    assert!(!deadline_output.exists());

    let output = directory.path().join("exact.tcr1");
    let args = prepare_args(&origin_path, &exact, &output, 42_000, 4);
    let prepared = cli(&args);
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let canonical = CellReleaseManifestV1::new(context, vec![first.id(), second.id()]).unwrap();
    assert_eq!(fs::read(&output).unwrap(), canonical.encode());
    let retry = cli(&args);
    assert!(!retry.status.success());
    assert!(String::from_utf8_lossy(&retry.stderr).contains("release marker exists"));
    assert_eq!(fs::read(&output).unwrap(), canonical.encode());
}
