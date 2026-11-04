//! Actual CLI opt-in to TCQ2/TCS2. Listening output is the only readiness signal;
//! a probe socket would incorrectly spend the single allowed connection.

use std::{
    fs::{self, OpenOptions},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use trnm_data_availability::cell::{digest_hex, CellCacheConfigV4, CellContextV1, CellStoreV1};

struct ChildOwner(Option<Child>);

impl ChildOwner {
    fn completed(&mut self) -> Child {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                return self.0.take().unwrap();
            }
            assert!(Instant::now() < deadline, "CLI child deadline");
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
    let child = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ChildOwner(Some(child))
        .completed()
        .wait_with_output()
        .unwrap()
}

fn read_log(path: &Path) -> Vec<u8> {
    assert!(
        fs::metadata(path).unwrap().len() <= 16_384,
        "bounded CLI log"
    );
    fs::read(path).unwrap()
}

fn arg(args: &mut Vec<String>, name: &str, value: impl ToString) {
    args.push(name.into());
    args.push(value.to_string());
}

fn remove(args: &mut Vec<String>, name: &str) {
    let index = args.iter().position(|value| value == name).unwrap();
    args.drain(index..index + 2);
}

fn replace(args: &mut [String], name: &str, value: &str) {
    let index = args.iter().position(|value| value == name).unwrap();
    args[index + 1] = value.into();
}

fn fetch_args(
    cache: &Path,
    output: &Path,
    pinned: &str,
    peer: &str,
    wire_bytes: u64,
) -> Vec<String> {
    let mut args = vec!["fetch".into()];
    for (name, value) in [
        ("--cache-max-bytes", "1048576"),
        ("--cache-max-chunks", "16"),
        ("--cache-max-manifests", "16"),
        ("--cache-max-db-bytes", "2097152"),
        ("--transport", "persistent-v2"),
        ("--max-requests", "3"),
        ("--max-requests-per-connection", "3"),
        ("--max-connections", "1"),
        ("--overall-ms", "5000"),
        ("--request-ms", "1500"),
        ("--parallelism", "2"),
        ("--max-bytes", "32768"),
    ] {
        arg(&mut args, name, value);
    }
    arg(&mut args, "--store", cache.display());
    arg(&mut args, "--output", output.display());
    arg(&mut args, "--manifest", pinned);
    arg(&mut args, "--peers", peer);
    arg(&mut args, "--max-response-bytes", wire_bytes);
    args
}

fn serve_args(store: &Path, wire_bytes: u64) -> Vec<String> {
    let mut args = vec!["serve".into()];
    for (name, value) in [
        ("--transport", "persistent-v2"),
        ("--bind", "127.0.0.1:0"),
        ("--seconds", "5"),
        ("--request-ms", "1500"),
        ("--max-connections", "1"),
        ("--bounded-workers", "1"),
        ("--max-requests", "3"),
        ("--max-requests-per-connection", "3"),
    ] {
        arg(&mut args, name, value);
    }
    arg(&mut args, "--store", store.display());
    arg(&mut args, "--max-served-bytes", wire_bytes);
    args
}

struct ServingChild {
    address: SocketAddr,
    child: ChildOwner,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl ServingChild {
    fn start(root: &Path, store: &Path, wire_bytes: u64) -> Self {
        let stdout = root.join("server.stdout");
        let stderr = root.join("server.stderr");
        let child = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
            .args(serve_args(store, wire_bytes))
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&stdout)
                    .unwrap(),
            ))
            .stderr(Stdio::from(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&stderr)
                    .unwrap(),
            ))
            .spawn()
            .unwrap();
        let mut child = ChildOwner(Some(child));
        let deadline = Instant::now() + Duration::from_secs(5);
        let address = loop {
            let bytes = read_log(&stdout);
            if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
                let ready: Value = serde_json::from_slice(&bytes[..end]).unwrap();
                assert_eq!(ready["schema"], "trnm.cell.listen.v1");
                break ready["address"]
                    .as_str()
                    .unwrap()
                    .parse::<SocketAddr>()
                    .unwrap();
            }
            assert!(
                child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "server failed before readiness: {}",
                String::from_utf8_lossy(&read_log(&stderr))
            );
            assert!(Instant::now() < deadline, "server readiness deadline");
            thread::sleep(Duration::from_millis(5));
        };
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        Self {
            address,
            child,
            stdout,
            stderr,
        }
    }

    fn finish(mut self) -> Value {
        let status = self.child.completed().wait().unwrap();
        assert!(
            status.success(),
            "{}",
            String::from_utf8_lossy(&read_log(&self.stderr))
        );
        let bytes = read_log(&self.stdout);
        let reports: Vec<Value> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(reports.len(), 2);
        reports[1].clone()
    }
}

#[test]
fn cli_downloads_real_manifest_and_multiple_chunks_through_one_explicit_v2_connection() {
    let dir = tempfile::tempdir().unwrap();
    let origin_path = dir.path().join("origin.sqlite");
    let origin = CellStoreV1::open(
        &origin_path,
        CellCacheConfigV4 {
            max_database_bytes: 2_097_152,
            max_logical_bytes: 1_048_576,
            max_chunk_rows: 16,
            max_manifest_rows: 16,
        },
    )
    .unwrap();
    let payload = [vec![7_u8; 16_384], vec![8_u8; 16_384]].concat();
    let input = dir.path().join("weights");
    fs::write(&input, &payload).unwrap();
    let manifest = origin
        .pack_file(
            &input,
            CellContextV1 {
                family: "persistent-cli".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            },
            16_384,
        )
        .unwrap();
    assert_eq!(manifest.chunks().len(), 2);
    drop(origin);
    let wire_bytes = manifest.encode().len() as u64 + payload.len() as u64 + 3 * 9;
    let server = ServingChild::start(dir.path(), &origin_path, wire_bytes);
    let cache = dir.path().join("receiver.sqlite");
    let output = dir.path().join("complete.weights");
    let accepted = cli(&fetch_args(
        &cache,
        &output,
        &digest_hex(manifest.id()),
        &server.address.to_string(),
        wire_bytes,
    ));
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let fetched: Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(fetched["schema"], "trnm.cell.fetch.persistent.v2");
    assert_eq!(fetched["request_attempts"], 3);
    assert_eq!(fetched["connection_attempts"], 1);
    assert_eq!(fetched["received_response_bytes"], wire_bytes);
    assert_eq!(fetched["downloaded_chunks"], 2);
    assert_eq!(fetched["cached_chunks"], 0);
    assert_eq!(fetched["bytes"], payload.len());
    assert_eq!(fs::read(output).unwrap(), payload);
    let served = server.finish();
    assert_eq!(served["schema"], "trnm.cell.serve.persistent.v2");
    assert_eq!(served["request_attempts"], 3);
    assert_eq!(served["connections"], 1);
    assert_eq!(served["completed"], 3);
    assert_eq!(served["sent_response_bytes"], wire_bytes);
}

#[test]
fn invalid_or_missing_request_bounds_and_unsupported_profile_combinations_fail_before_cache_creation(
) {
    let dir = tempfile::tempdir().unwrap();
    let cases = [
        ("missing", "--max-requests", ""),
        ("missing", "--max-requests-per-connection", ""),
        ("replace", "--max-requests", "0"),
        ("replace", "--max-requests", "100001"),
        ("replace", "--max-requests", "-1"),
        ("replace", "--max-requests-per-connection", "0"),
        ("replace", "--max-requests-per-connection", "4"),
        ("replace", "--transport", "unknown-v2"),
        ("replace", "--transport", "single-request-v1"),
        ("add", "--scheduling", "rarest-first-v1"),
    ];
    for (index, (action, name, value)) in cases.into_iter().enumerate() {
        let cache = dir.path().join(format!("cache-{index}.sqlite"));
        let output = dir.path().join(format!("output-{index}"));
        let mut args = fetch_args(&cache, &output, &digest_hex([1; 32]), "127.0.0.1:9", 65_536);
        match action {
            "missing" => remove(&mut args, name),
            "replace" => replace(&mut args, name, value),
            "add" => arg(&mut args, name, value),
            _ => unreachable!(),
        }
        let refused = cli(&args);
        assert!(!refused.status.success(), "case {index}");
        assert!(
            !cache.exists(),
            "case {index} created the cache before rejecting invalid input"
        );
        assert!(!output.exists(), "case {index}");
        assert!(refused.stdout.is_empty(), "case {index}");
    }
}

#[test]
fn persistent_cli_server_requires_bounded_workers_and_each_request_allowance() {
    let dir = tempfile::tempdir().unwrap();
    for missing in [
        "--bounded-workers",
        "--max-served-bytes",
        "--max-requests",
        "--max-requests-per-connection",
    ] {
        let path = dir.path().join(format!("missing-{missing}.sqlite"));
        let mut args = serve_args(&path, 65_536);
        remove(&mut args, missing);
        let refused = cli(&args);
        assert!(!refused.status.success(), "{missing}");
        assert!(!path.exists(), "{missing}");
        assert!(
            refused.stdout.is_empty(),
            "{missing} emitted a listening record before input validation"
        );
    }
}
