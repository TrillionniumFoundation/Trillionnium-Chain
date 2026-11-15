//! The ordinary binary must validate real tensor bytes before its final marker.
#![cfg(unix)]

use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use trnm_data_availability::cell::*;

fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 8 * 1024 * 1024,
        max_logical_bytes: 1024 * 1024,
        max_chunk_rows: 64,
        max_manifest_rows: 16,
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    origin: PathBuf,
    model: CellTensorModelManifestV1,
    payload: Vec<u8>,
}

impl Fixture {
    fn new(dtype: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let origin = directory.path().join("origin.db");
        let header = format!(
            "{{\"weight\":{{\"dtype\":\"{dtype}\",\"shape\":[8192],\"data_offsets\":[0,32768]}}}}"
        );
        let mut payload = (header.len() as u64).to_le_bytes().to_vec();
        payload.extend(header.as_bytes());
        // Three chunks exercise reads across header/data and chunk boundaries.
        payload.extend((0..8192_u32).flat_map(|i| (i as f32).to_le_bytes()));
        let input = directory.path().join("source.safetensors");
        fs::write(&input, &payload).unwrap();
        let context = CellContextV1 {
            family: "tensor-cli-test".into(),
            base: [1; 32],
            parent: [2; 32],
            tokenizer: [3; 32],
            layout: [4; 32],
            runtime: [5; 32],
        };
        let store = CellStoreV1::open(&origin, config()).unwrap();
        let manifest = store.pack_file(&input, context.clone(), 16_384).unwrap();
        let closure = CellReleaseClosureV1::new(
            context,
            7,
            [6; 32],
            vec![0],
            vec![CellClosureFileV1 {
                path: "base/model.safetensors".into(),
                role: CellFileRoleV1::Base,
                manifest: manifest.id(),
                payload_sha256: manifest.payload_sha256(),
                payload_bytes: manifest.size(),
                dependencies: vec![],
            }],
        )
        .unwrap();
        let root = CellModelReleaseRootV1::new(closure, vec![]).unwrap();
        let contract = CellTensorContractV1::new(
            root.id(),
            vec![CellTensorFileV1 {
                file_index: 0,
                tensors: vec![CellTensorSpecV1 {
                    name: "weight".into(),
                    dtype: CellTensorDTypeV1::F32,
                    shape: vec![8192],
                }],
            }],
        )
        .unwrap();
        let model = CellTensorModelManifestV1::new(root, contract).unwrap();
        fs::write(directory.path().join("owner.tma1"), model.encode()).unwrap();
        Self {
            directory,
            origin,
            model,
            payload,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn args(&self, peers: &str, store: &str, output: &str) -> Vec<String> {
        let closure = self.model.root().closure();
        let context = closure.release().context();
        let mut args = vec!["fetch-tensor-model".to_owned()];
        for (key, value) in [
            ("--authentication-profile", "content-cache-v1".into()),
            ("--store", self.path(store).display().to_string()),
            ("--cache-max-bytes", config().max_logical_bytes.to_string()),
            ("--cache-max-chunks", config().max_chunk_rows.to_string()),
            (
                "--cache-max-manifests",
                config().max_manifest_rows.to_string(),
            ),
            (
                "--cache-max-db-bytes",
                config().max_database_bytes.to_string(),
            ),
            (
                "--tensor-model-file",
                self.path("owner.tma1").display().to_string(),
            ),
            ("--tensor-model", digest_hex(self.model.id())),
            ("--closure", digest_hex(closure.id())),
            ("--loader-generation", "7".into()),
            ("--loader-profile", digest_hex([6; 32])),
            ("--required-roles", "base".into()),
            ("--family", context.family.clone()),
            ("--base", digest_hex(context.base)),
            ("--parent", digest_hex(context.parent)),
            ("--tokenizer", digest_hex(context.tokenizer)),
            ("--layout", digest_hex(context.layout)),
            ("--runtime", digest_hex(context.runtime)),
            ("--peers", peers.into()),
            ("--output", self.path(output).display().to_string()),
            ("--max-bytes", self.payload.len().to_string()),
            ("--max-chunks", "3".into()),
            ("--overall-ms", "5000".into()),
            ("--request-ms", "500".into()),
            ("--parallelism", "2".into()),
            ("--max-connections", "4".into()),
            ("--max-response-bytes", "40000".into()),
        ] {
            args.push(key.into());
            args.push(value);
        }
        args
    }

    fn persistent_args(
        &self,
        peers: &str,
        store: &str,
        output: &str,
        max_requests: u64,
    ) -> Vec<String> {
        let mut args = self.args(peers, store, output);
        for (key, value) in [
            ("--max-connections", "1"),
            ("--parallelism", "1"),
            ("--request-ms", "2000"),
            ("--overall-ms", "10000"),
        ] {
            set_arg(&mut args, key, value);
        }
        for (key, value) in [
            ("--transport", "persistent-v2".to_owned()),
            ("--max-requests", max_requests.to_string()),
            ("--max-requests-per-connection", max_requests.to_string()),
        ] {
            args.push(key.into());
            args.push(value);
        }
        args
    }
}

fn set_arg(args: &mut [String], key: &str, value: &str) {
    let index = args.iter().position(|argument| argument == key).unwrap();
    args[index + 1] = value.into();
}

struct PersistentServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: thread::JoinHandle<CellPersistentServeReportV2>,
}

impl PersistentServer {
    fn start(fixture: &Fixture, max_requests: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let origin = fixture.origin.clone();
        let worker = thread::spawn(move || {
            serve_cells_persistent(
                &listener,
                &origin,
                &server_stop,
                CellPersistentServeLimitsV2 {
                    serving: CellServeLimitsV1 {
                        request_timeout: Duration::from_secs(2),
                        overall_timeout: Duration::from_secs(10),
                        max_workers: 1,
                        max_connections: 1,
                        max_response_bytes: 40_000,
                    },
                    max_requests,
                    max_requests_per_connection: max_requests,
                },
            )
            .unwrap()
        });
        Self {
            address,
            stop,
            worker,
        }
    }

    fn finish(self) -> CellPersistentServeReportV2 {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.join().unwrap()
    }
}

#[test]
fn real_tcp_tensor_model_publishes_exact_manifest_then_revalidates_without_origin() {
    let fixture = Fixture::new("F32");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let origin = fixture.origin.clone();
    let server = thread::spawn(move || {
        let store = CellStoreV1::open_read_only(&origin).unwrap();
        serve_cells(
            &listener,
            &store,
            &server_stop,
            CellPeerLimitsV1 {
                request_timeout: Duration::from_millis(500),
                overall_timeout: Duration::from_secs(10),
                max_cell_bytes: 1024 * 1024,
                parallelism: 1,
                max_connections: 4,
                max_response_bytes: 0,
            },
        )
        .unwrap()
    });
    let output = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(fixture.args(&address.to_string(), "consumer.db", "complete.tma1"))
        .output()
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    let served = server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(served, 4);
    assert_eq!(
        fs::read(fixture.path("complete.tma1")).unwrap(),
        fixture.model.encode()
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["tensor_files"], 1);
    assert_eq!(report["selection_authority"], false);
    assert_eq!(report["use_authority"], false);
    assert_eq!(report["downloaded_bytes"], fixture.payload.len() as u64);
    let mut args = fixture.args("", "consumer.db", "cache-only.tma1");
    let budget = args
        .iter()
        .position(|x| x == "--max-response-bytes")
        .unwrap();
    args[budget + 1] = "0".into();
    let cached = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        cached.status.success(),
        "{}",
        String::from_utf8_lossy(&cached.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&cached.stdout).unwrap();
    assert_eq!(report["connection_attempts"], 0);
    assert_eq!(report["received_response_bytes"], 0);
    assert_eq!(
        fs::read(fixture.path("cache-only.tma1")).unwrap(),
        fixture.model.encode()
    );
}

#[test]
fn hash_correct_container_with_wrong_dtype_never_publishes_tensor_completion() {
    let fixture = Fixture::new("I32");
    let store = CellStoreV1::open(&fixture.origin, config()).unwrap();
    // The original byte-only contract succeeds: this is a metadata failure,
    // not a deliberately corrupt hash standing in for a parser check.
    store
        .verify_complete(
            &store
                .manifest(fixture.model.root().closure().files()[0].manifest)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    drop(store);
    let output = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(fixture.args("", "origin.db", "forbidden.tma1"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("tensor roster metadata"));
    assert!(!fixture.path("forbidden.tma1").exists());
}

#[test]
fn wrong_tensor_manifest_pin_is_rejected_before_cache_creation() {
    let fixture = Fixture::new("F32");
    let mut args = fixture.args("127.0.0.1:1", "absent.db", "absent.tma1");
    let index = args.iter().position(|x| x == "--tensor-model").unwrap();
    args[index + 1] = digest_hex([99; 32]);
    let output = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(args)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!fixture.path("absent.db").exists());
    assert!(!fixture.path("absent.tma1").exists());
}

#[test]
fn persistent_tensor_cli_shares_one_connection_and_four_requests_across_manifest_and_chunks() {
    let fixture = Fixture::new("F32");
    let server = PersistentServer::start(&fixture, 4);
    let output = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(fixture.persistent_args(
            &server.address.to_string(),
            "persistent.db",
            "persistent.tma1",
            4,
        ))
        .output()
        .unwrap();
    let served = server.finish();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "trnm.cell.tensor-model.fetch.v1");
    assert_eq!(report["transport"], "persistent-v2");
    assert_eq!(report["request_attempts"], 4);
    assert_eq!(report["connection_attempts"], 1);
    assert_eq!(report["downloaded_bytes"], fixture.payload.len() as u64);
    assert_eq!(report["tensor_files"], 1);
    assert_eq!(report["selection_authority"], false);
    assert_eq!(report["use_authority"], false);
    assert_eq!(served.request_attempts, 4);
    assert_eq!(served.serving.accepted_connections, 1);
    assert_eq!(served.serving.completed_requests, 4);
    assert_eq!(
        report["received_response_bytes"],
        served.serving.sent_response_bytes
    );
    assert_eq!(
        fs::read(fixture.path("persistent.tma1")).unwrap(),
        fixture.model.encode()
    );
    let mut cached_args = fixture.persistent_args("", "persistent.db", "persistent-cached.tma1", 1);
    set_arg(&mut cached_args, "--max-response-bytes", "0");
    let cached = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(cached_args)
        .output()
        .unwrap();
    assert!(
        cached.status.success(),
        "{}",
        String::from_utf8_lossy(&cached.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&cached.stdout).unwrap();
    assert_eq!(report["transport"], "persistent-v2");
    assert_eq!(report["request_attempts"], 0);
    assert_eq!(report["connection_attempts"], 0);
    assert_eq!(report["received_response_bytes"], 0);
    assert_eq!(
        fs::read(fixture.path("persistent-cached.tma1")).unwrap(),
        fixture.model.encode()
    );
}

#[test]
fn persistent_rarest_tensor_cli_verifies_complete_model_and_then_works_cache_only() {
    let fixture = Fixture::new("F32");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let origin = fixture.origin.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        serve_cells_persistent_rarest_first_with_ready(
            &listener,
            &origin,
            &AtomicBool::new(false),
            CellPersistentServeLimitsV2 {
                serving: CellServeLimitsV1 {
                    request_timeout: Duration::from_secs(2),
                    overall_timeout: Duration::from_secs(5),
                    max_workers: 1,
                    max_connections: 1,
                    max_response_bytes: 40_000,
                },
                max_requests: 5,
                max_requests_per_connection: 5,
            },
            &|| {
                ready_tx
                    .send(())
                    .map_err(|_| CellErrorV1::Invalid("test ready receiver"))
            },
        )
        .unwrap()
    });
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let mut args = fixture.persistent_args(&address.to_string(), "rarest.db", "rarest.tma1", 5);
    set_arg(&mut args, "--transport", "persistent-rarest-v3");
    args.extend(["--scheduling".into(), "rarest-first-v1".into()]);
    let output = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(args)
        .output()
        .unwrap();
    let served = worker.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["transport"], "persistent-rarest-v3");
    assert_eq!(report["request_attempts"], 5);
    assert_eq!(report["connection_attempts"], 1);
    assert_eq!(report["downloaded_bytes"], fixture.payload.len() as u64);
    assert_eq!(report["tensor_files"], 1);
    assert_eq!(report["selection_authority"], false);
    assert_eq!(report["use_authority"], false);
    assert_eq!(
        report["received_response_bytes"],
        served.serving.sent_response_bytes
    );
    assert_eq!(served.request_attempts, 5);
    assert_eq!(served.serving.completed_requests, 5);
    assert_eq!(served.serving.accepted_connections, 1);
    assert_eq!(
        fs::read(fixture.path("rarest.tma1")).unwrap(),
        fixture.model.encode()
    );
    let mut cached_args = fixture.persistent_args("", "rarest.db", "rarest-cached.tma1", 1);
    set_arg(&mut cached_args, "--transport", "persistent-rarest-v3");
    set_arg(&mut cached_args, "--max-response-bytes", "0");
    cached_args.extend(["--scheduling".into(), "rarest-first-v1".into()]);
    let cached = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(cached_args)
        .output()
        .unwrap();
    assert!(
        cached.status.success(),
        "{}",
        String::from_utf8_lossy(&cached.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&cached.stdout).unwrap();
    assert_eq!(report["transport"], "persistent-rarest-v3");
    assert_eq!(report["request_attempts"], 0);
    assert_eq!(report["connection_attempts"], 0);
    assert_eq!(report["received_response_bytes"], 0);
    assert_eq!(
        fs::read(fixture.path("rarest-cached.tma1")).unwrap(),
        fixture.model.encode()
    );
}

#[test]
fn persistent_tensor_cli_keeps_verified_prefix_on_request_exhaustion_and_explicit_retry_resumes() {
    let fixture = Fixture::new("F32");
    let server = PersistentServer::start(&fixture, 2);
    let failed = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(fixture.persistent_args(
            &server.address.to_string(),
            "resume.db",
            "incomplete.tma1",
            2,
        ))
        .output()
        .unwrap();
    let served = server.finish();
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr)
        .contains("CELL_PERSISTENT_REQUEST_BUDGET_EXHAUSTED"));
    assert!(!fixture.path("incomplete.tma1").exists());
    assert_eq!(served.request_attempts, 2);
    assert_eq!(served.serving.accepted_connections, 1);
    assert_eq!(served.serving.completed_requests, 2);
    let cache = CellStoreV1::open_read_only(&fixture.path("resume.db")).unwrap();
    let manifest = cache
        .manifest(fixture.model.root().closure().files()[0].manifest)
        .unwrap()
        .unwrap();
    assert_eq!(manifest.chunks().len(), 3);
    assert_eq!(
        cache.chunk(manifest.chunks()[0].sha256).unwrap(),
        Some(fixture.payload[..16_384].to_vec())
    );
    for chunk in &manifest.chunks()[1..] {
        assert!(cache.chunk(chunk.sha256).unwrap().is_none());
    }
    assert!(cache.verify_complete(&manifest).is_err());
    drop(cache);

    // This new CLI invocation owns a fresh reservation. The old operation did
    // not renew its frame, connection or response-byte allowance on failure.
    let retry = PersistentServer::start(&fixture, 2);
    let resumed = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
        .args(fixture.persistent_args(&retry.address.to_string(), "resume.db", "resumed.tma1", 2))
        .output()
        .unwrap();
    let served = retry.finish();
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&resumed.stdout).unwrap();
    assert_eq!(report["transport"], "persistent-v2");
    assert_eq!(report["request_attempts"], 2);
    assert_eq!(report["connection_attempts"], 1);
    assert_eq!(
        report["downloaded_bytes"],
        fixture.payload.len() as u64 - 16_384
    );
    assert_eq!(served.request_attempts, 2);
    assert_eq!(served.serving.accepted_connections, 1);
    assert_eq!(served.serving.completed_requests, 2);
    assert_eq!(
        report["received_response_bytes"],
        served.serving.sent_response_bytes
    );
    assert_eq!(
        fs::read(fixture.path("resumed.tma1")).unwrap(),
        fixture.model.encode()
    );
}

#[test]
fn invalid_persistent_tensor_transport_combinations_refuse_before_cache_creation() {
    let fixture = Fixture::new("F32");
    for case in [
        "rarest-first",
        "per-connection-exceeds-total",
        "zero-requests",
    ] {
        let store = format!("{case}.db");
        let marker = format!("{case}.tma1");
        let mut args = fixture.persistent_args("127.0.0.1:1", &store, &marker, 4);
        match case {
            "rarest-first" => args.extend(["--scheduling".into(), "rarest-first-v1".into()]),
            "per-connection-exceeds-total" => {
                set_arg(&mut args, "--max-requests-per-connection", "5")
            }
            "zero-requests" => set_arg(&mut args, "--max-requests", "0"),
            _ => unreachable!(),
        }
        let output = Command::new(env!("CARGO_BIN_EXE_trnm-cell"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{case}");
        let error = String::from_utf8_lossy(&output.stderr);
        let expected = if case == "rarest-first" {
            "persistent transport requires ordered scheduling"
        } else {
            "persistent request bounds"
        };
        assert!(error.contains(expected), "{case}: {error}");
        assert!(!fixture.path(&store).exists(), "{case}");
        assert!(!fixture.path(&marker).exists(), "{case}");
    }
}
