//! Real CLI startup and TCP transfer: a ready event spends no probe socket.
use serde_json::Value;
use std::{
    fs::{self, File},
    net::SocketAddr,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use trnm_data_availability::cell::{
    fetch_cell, fetch_cell_persistent, CellCacheConfigV4, CellContextV1, CellPeerLimitsV1,
    CellPersistentPeerLimitsV2, CellStoreV1,
};

struct ChildOwner(Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 4 * 1024 * 1024,
        max_logical_bytes: 1024 * 1024,
        max_chunk_rows: 8,
        max_manifest_rows: 8,
    }
}

fn events(path: &Path) -> Vec<Value> {
    let raw = fs::read(path).unwrap();
    assert!(raw.len() <= 8192);
    // A partial final line is not an event.
    raw.split_inclusive(|byte| *byte == b'\n')
        .filter(|line| line.ends_with(b"\n"))
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn service(cache: &Path, log: &Path, persistent: bool) -> ChildOwner {
    let mut command = Command::new(env!("CARGO_BIN_EXE_trnm-cell"));
    command.args(["serve", "--store"]).arg(cache).args([
        "--bind",
        "127.0.0.1:0",
        "--seconds",
        "5",
        "--request-ms",
        "1000",
        "--bounded-workers",
        "2",
        "--max-connections",
        "1",
        "--max-served-bytes",
        "1048576",
        "--announce-ready",
        "true",
    ]);
    if persistent {
        command.args([
            "--transport",
            "persistent-v2",
            "--max-requests",
            "1",
            "--max-requests-per-connection",
            "1",
        ]);
    }
    ChildOwner(
        command
            .stdin(Stdio::null())
            .stdout(File::create(log).unwrap())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

#[test]
fn provider_ready_cli_preserves_the_only_connection_for_actual_payload() {
    for persistent in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let payload = vec![0x5a; 16 * 1024];
        let input = root.path().join("payload");
        fs::write(&input, &payload).unwrap();
        let cache = root.path().join("provider.sqlite");
        let producer = CellStoreV1::open(&cache, config()).unwrap();
        let manifest = producer
            .pack_file(
                &input,
                CellContextV1 {
                    family: "ready-cli-control".into(),
                    base: [1; 32],
                    parent: [2; 32],
                    tokenizer: [3; 32],
                    layout: [4; 32],
                    runtime: [5; 32],
                },
                16 * 1024,
            )
            .unwrap();
        drop(producer);
        let log = root.path().join("provider.jsonl");
        let mut child = service(&cache, &log, persistent);
        let deadline = Instant::now() + Duration::from_secs(5);
        let startup = loop {
            let rows = events(&log);
            if rows.len() >= 2 {
                break rows;
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "provider exited before ready"
            );
            assert!(Instant::now() < deadline, "provider ready deadline");
            thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(startup[0]["schema"], "trnm.cell.listen.v1");
        assert_eq!(startup[1]["schema"], "trnm.cell.ready.v1");
        assert_eq!(startup[0]["address"], startup[1]["address"]);
        let address: SocketAddr = startup[1]["address"].as_str().unwrap().parse().unwrap();
        let consumer = CellStoreV1::open(&root.path().join("consumer.sqlite"), config()).unwrap();
        // Owner-pinned manifest is local. The single connection must carry the
        // real missing payload, never a separate readiness probe.
        consumer
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
        let peer = CellPeerLimitsV1 {
            request_timeout: Duration::from_secs(1),
            overall_timeout: Duration::from_secs(3),
            max_cell_bytes: payload.len() as u64,
            parallelism: 1,
            max_connections: 1,
            max_response_bytes: 1024 * 1024,
        };
        let report = if persistent {
            let (_, report) = fetch_cell_persistent(
                &consumer,
                manifest.id(),
                &[address],
                CellPersistentPeerLimitsV2 {
                    peer,
                    max_requests: 1,
                    max_requests_per_connection: 1,
                },
            )
            .unwrap();
            assert_eq!(report.request_attempts, 1);
            report.fetch
        } else {
            fetch_cell(&consumer, manifest.id(), &[address], peer)
                .unwrap()
                .1
        };
        assert_eq!(report.connection_attempts, 1);
        assert_eq!(report.downloaded_bytes, payload.len() as u64);
        assert_eq!(
            consumer
                .chunk(manifest.chunks()[0].sha256)
                .unwrap()
                .unwrap(),
            payload
        );
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "provider join deadline");
            thread::sleep(Duration::from_millis(5));
        }
        let rows = events(&log);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2]["connections"], 1);
        assert_eq!(rows[2]["completed"], 1);
    }
}

#[test]
fn provider_ready_cli_never_advertises_an_invalid_cache_as_ready() {
    for persistent in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("invalid.sqlite");
        fs::write(&cache, b"not a validated Cell cache").unwrap();
        let log = root.path().join("provider.jsonl");
        let mut child = service(&cache, &log, persistent);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(!status.success());
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        let rows = events(&log);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["schema"], "trnm.cell.listen.v1");
    }
}
