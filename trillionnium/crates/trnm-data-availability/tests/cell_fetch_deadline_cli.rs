//! Actual fetch CLI deadline parsing and bounded TCP delivery. No model authority.

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
    digest_hex, serve_cells, CellContextV1, CellPeerLimitsV1, CellStoreV1,
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
            let store = CellStoreV1::open(&path, cache_config()).unwrap();
            serve_cells(
                &listener,
                &store,
                &child_stop,
                CellPeerLimitsV1 {
                    request_timeout: Duration::from_secs(2),
                    overall_timeout: Duration::from_secs(20),
                    max_cell_bytes: 655,
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

fn fetch_args(cache: &Path, output: &Path, pinned: &str, peer: &str) -> Vec<String> {
    vec![
        "fetch".into(),
        "--cache-max-bytes".into(),
        "67108864".into(),
        "--cache-max-chunks".into(),
        "4096".into(),
        "--cache-max-manifests".into(),
        "256".into(),
        "--store".into(),
        cache.display().to_string(),
        "--manifest".into(),
        pinned.into(),
        "--peers".into(),
        peer.into(),
        "--output".into(),
        output.display().to_string(),
        "--max-bytes".into(),
        "655".into(),
    ]
}

#[test]
fn cli_delivers_real_uncached_bytes_with_seconds_and_subtwo_second_milliseconds() {
    let directory = tempfile::tempdir().unwrap();
    let origin_path = directory.path().join("origin.sqlite");
    let origin = CellStoreV1::open(&origin_path, cache_config()).unwrap();
    let input = directory.path().join("input");
    let bytes = vec![7; 655];
    fs::write(&input, &bytes).unwrap();
    let manifest = origin
        .pack_file(
            &input,
            CellContextV1 {
                family: "deadline-cli-v1".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            },
            16_384,
        )
        .unwrap();
    let peer = Peer::new(&origin_path);
    let pinned = digest_hex(manifest.id());
    let address = peer.address.to_string();
    for (index, deadline_args) in [
        vec!["--seconds", "3"],
        vec!["--overall-ms", "1500", "--request-ms", "1500"],
        vec!["--overall-ms", "750", "--request-ms", "750"],
    ]
    .into_iter()
    .enumerate()
    {
        let output = directory.path().join(format!("output-{index}"));
        let mut args = fetch_args(
            &directory.path().join(format!("cache-{index}.sqlite")),
            &output,
            &pinned,
            &address,
        );
        args.extend(deadline_args.into_iter().map(String::from));
        let accepted = cli(&args);
        assert!(
            accepted.status.success(),
            "{}",
            String::from_utf8_lossy(&accepted.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&accepted.stdout).unwrap();
        assert_eq!(report["downloaded_chunks"], 1);
        assert_eq!(report["cached_chunks"], 0);
        assert_eq!(report["connection_attempts"], 2);
        assert_eq!(report["bytes"], 655);
        assert_eq!(fs::read(&output).unwrap(), bytes);
    }
    assert_eq!(peer.finish(), 6);
}

#[test]
fn cli_requires_exactly_one_deadline_unit_and_a_positive_bounded_duration() {
    let directory = tempfile::tempdir().unwrap();
    for (index, deadline_args) in [
        vec![],
        vec!["--seconds", "3", "--overall-ms", "3000"],
        vec!["--overall-ms", "0"],
        vec!["--overall-ms", "-1"],
        vec!["--overall-ms", "86400001"],
        vec!["--overall-ms", "18446744073709551616"],
        vec!["--seconds", "0"],
    ]
    .into_iter()
    .enumerate()
    {
        let output = directory.path().join(format!("output-{index}"));
        let cache = directory.path().join(format!("cache-{index}.sqlite"));
        let mut args = fetch_args(&cache, &output, &digest_hex([1; 32]), "127.0.0.1:9");
        args.extend(deadline_args.into_iter().map(String::from));
        let rejected = cli(&args);
        assert!(!rejected.status.success(), "case {index}");
        assert!(!output.exists(), "case {index}");
        if index < 2 {
            assert!(String::from_utf8_lossy(&rejected.stderr).contains("exactly one"));
            assert!(!cache.exists());
        }
    }
}

#[test]
fn cli_preserves_original_request_minimum_and_overall_must_cover_request() {
    let directory = tempfile::tempdir().unwrap();
    for (index, deadline_args) in [
        vec!["--seconds", "1"],
        vec!["--overall-ms", "1500"],
        vec!["--overall-ms", "10", "--request-ms", "9"],
        vec!["--overall-ms", "9", "--request-ms", "10"],
        vec!["--overall-ms", "50000", "--request-ms", "30001"],
    ]
    .into_iter()
    .enumerate()
    {
        let output = directory.path().join(format!("output-{index}"));
        let mut args = fetch_args(
            &directory.path().join(format!("cache-{index}.sqlite")),
            &output,
            &digest_hex([1; 32]),
            "127.0.0.1:9",
        );
        args.extend(deadline_args.into_iter().map(String::from));
        let rejected = cli(&args);
        assert!(!rejected.status.success(), "case {index}");
        let reason = if index == 2 || index == 4 {
            "request deadline"
        } else {
            "overall deadline"
        };
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains(reason),
            "case {index}: {}",
            String::from_utf8_lossy(&rejected.stderr)
        );
        assert!(!output.exists());
    }
}

#[test]
fn cli_requires_each_persistent_quota_before_creating_a_writer_cache() {
    let directory = tempfile::tempdir().unwrap();
    for missing in [
        "--cache-max-bytes",
        "--cache-max-chunks",
        "--cache-max-manifests",
    ] {
        let cache = directory.path().join(missing);
        let output = directory.path().join(format!("{missing}-output"));
        let mut args = fetch_args(&cache, &output, &digest_hex([1; 32]), "");
        let index = args.iter().position(|value| value == missing).unwrap();
        args.drain(index..index + 2);
        args.extend(["--seconds".into(), "3".into()]);
        let rejected = cli(&args);
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains(missing));
        assert!(!cache.exists());
        assert!(!output.exists());
    }
}

#[test]
fn cli_manifest_reads_persisted_caps_and_cannot_create_a_missing_cache() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.sqlite");
    let cache = CellStoreV1::open(&path, cache_config()).unwrap();
    let source = directory.path().join("source");
    fs::write(&source, b"finite persisted cache").unwrap();
    let manifest = cache
        .pack_file(
            &source,
            CellContextV1 {
                family: "quota-cli-v2".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            },
            16_384,
        )
        .unwrap();
    let before = cache.cache_usage().unwrap();
    let output = directory.path().join("wire");
    let args = vec![
        "manifest".into(),
        "--store".into(),
        path.display().to_string(),
        "--manifest".into(),
        digest_hex(manifest.id()),
        "--output".into(),
        output.display().to_string(),
    ];
    let read = cli(&args);
    assert!(
        read.status.success(),
        "{}",
        String::from_utf8_lossy(&read.stderr)
    );
    assert_eq!(fs::read(output).unwrap(), manifest.encode());
    assert_eq!(cache.cache_usage().unwrap(), before);
    let missing = directory.path().join("missing.sqlite");
    let mut args = args;
    args[2] = missing.display().to_string();
    args[6] = directory
        .path()
        .join("missing-output")
        .display()
        .to_string();
    let refused = cli(&args);
    assert!(!refused.status.success());
    assert!(!missing.exists());
}

// Explicit finite fixture quota; covers the existing <=32MiB commit fixtures.
fn cache_config() -> trnm_data_availability::cell::CellCacheConfigV2 {
    trnm_data_availability::cell::CellCacheConfigV2 {
        max_logical_bytes: 64 * 1024 * 1024,
        max_chunk_rows: 4096,
        max_manifest_rows: 256,
    }
}
