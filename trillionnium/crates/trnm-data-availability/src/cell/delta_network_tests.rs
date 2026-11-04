//! Independent TCP composition checks for the original TCX1/CAS fetch owner.

use std::{
    fs, io,
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use super::*;

fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 4 * 1024 * 1024,
        max_logical_bytes: 2 * 1024 * 1024,
        max_chunk_rows: 32,
        max_manifest_rows: 16,
    }
}

fn context(parent: u8) -> CellContextV1 {
    CellContextV1 {
        family: "delta-tcp-test".into(),
        base: [1; 32],
        parent: [parent; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}

fn limits() -> CellReleaseFetchLimitsV1 {
    CellReleaseFetchLimitsV1 {
        peer: CellPeerLimitsV1 {
            request_timeout: Duration::from_secs(2),
            overall_timeout: Duration::from_secs(10),
            max_cell_bytes: 32_768,
            parallelism: 1,
            max_connections: 1,
            max_response_bytes: 16_384 + 9,
        },
        release: CellReleaseLimitsV1 {
            max_payload_bytes: 16_384 + 32_768,
            max_chunks: 3,
            deadline: Instant::now() + Duration::from_secs(10),
        },
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    client: CellStoreV1,
    base: CellManifestV1,
    target: CellManifestV1,
    delta: CellChunkDeltaV1,
    target_bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let base_input = dir.path().join("base.input");
        let target_input = dir.path().join("target.input");
        let base_bytes = vec![7; 16_384];
        let target_bytes = [base_bytes.clone(), vec![11; 16_384]].concat();
        fs::write(&base_input, &base_bytes).unwrap();
        fs::write(&target_input, &target_bytes).unwrap();
        let client = CellStoreV1::open(&dir.path().join("client.sqlite"), config()).unwrap();
        let base = client.pack_file(&base_input, context(2), 16_384).unwrap();
        let origin = CellStoreV1::open(&dir.path().join("origin.sqlite"), config()).unwrap();
        let target = origin.pack_file(&target_input, context(6), 16_384).unwrap();
        let delta = CellChunkDeltaV1::between(&base, &target).unwrap();
        assert_eq!(base.chunks()[0], target.chunks()[0]);
        assert_ne!(base.chunks()[0], target.chunks()[1]);
        assert!(client.manifest(target.id()).unwrap().is_none());
        assert!(client.chunk(target.chunks()[1].sha256).unwrap().is_none());
        Self {
            dir,
            client,
            base,
            target,
            delta,
            target_bytes,
        }
    }

    fn pins(&self) -> (CellDigestV1, CellDigestV1, CellDigestV1) {
        (self.delta.id(), self.base.id(), self.target.id())
    }
}

#[test]
fn tcp_delta_fetch_downloads_only_the_absent_chunk_and_materializes_exact_target() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let origin_path = fixture.dir.path().join("origin.sqlite");
    let server = thread::spawn(move || {
        serve_cells_bounded(
            &listener,
            &origin_path,
            &shutdown,
            CellServeLimitsV1 {
                request_timeout: Duration::from_secs(2),
                overall_timeout: Duration::from_secs(10),
                max_workers: 2,
                max_connections: 4,
                max_response_bytes: 16_384 + 9,
            },
        )
    });
    let output = fixture.dir.path().join("complete-target.weights");
    let result = fetch_delta_to_file(
        &fixture.client,
        &fixture.delta,
        fixture.pins(),
        &[peer],
        limits(),
        &output,
    );
    stop.store(true, Ordering::Relaxed);
    let served = server.join().unwrap().unwrap();
    let (plan, observed) = result.unwrap();
    assert_eq!(plan.reused_chunks, 1);
    assert_eq!(plan.reused_bytes, 16_384);
    assert_eq!(plan.new_chunks, 1);
    assert_eq!(plan.new_bytes, 16_384);
    assert_eq!(observed.manifest_id, fixture.target.id());
    assert_eq!(observed.payload_sha256, fixture.target.payload_sha256());
    assert_eq!(observed.cached_chunks, 1);
    assert_eq!(observed.downloaded_chunks, 1);
    assert_eq!(observed.downloaded_bytes, 16_384);
    assert_eq!(observed.connection_attempts, 1);
    assert_eq!(observed.received_response_bytes, 16_384 + 9);
    assert_eq!(observed.rejected_responses, 0);
    assert_eq!(served.accepted_connections, 1);
    assert_eq!(served.completed_requests, 1);
    assert_eq!(served.sent_response_bytes, observed.received_response_bytes);
    assert_eq!(fs::read(output).unwrap(), fixture.target_bytes);
    fixture.client.verify_complete(&fixture.target).unwrap();
    fixture.client.verify_complete(&fixture.base).unwrap();
}

#[test]
fn invalid_base_or_original_delta_budget_never_dials_or_publishes_target() {
    let fixture = Fixture::new();
    // A listening socket exposes even an attempted connection in its backlog.
    // No mock network result or synthetic transport observation is involved.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let peer = listener.local_addr().unwrap();
    let output = fixture.dir.path().join("must-not-exist");
    let mut wrong_base = fixture.pins();
    wrong_base.1 = [99; 32];
    assert!(matches!(
        fetch_delta_to_file(
            &fixture.client,
            &fixture.delta,
            wrong_base,
            &[peer],
            limits(),
            &output
        ),
        Err(CellErrorV1::Invalid("delta owner pins"))
    ));
    for (case, expected) in [
        (0, "delta payload budget"),
        (1, "delta chunk budget"),
        (2, "cell exceeds byte budget"),
    ] {
        let mut bounded = limits();
        match case {
            0 => bounded.release.max_payload_bytes -= 1,
            1 => bounded.release.max_chunks -= 1,
            2 => bounded.peer.max_cell_bytes = 16_384,
            _ => unreachable!(),
        }
        assert!(matches!(
            fetch_delta_to_file(&fixture.client, &fixture.delta, fixture.pins(), &[peer], bounded, &output),
            Err(CellErrorV1::Invalid(reason)) if reason == expected
        ));
        assert!(!output.exists());
        assert!(fixture
            .client
            .manifest(fixture.target.id())
            .unwrap()
            .is_none());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    // The correct manifest pin cannot excuse corrupt actual base bytes.
    let external = rusqlite::Connection::open(fixture.dir.path().join("client.sqlite")).unwrap();
    external
        .execute(
            "UPDATE cell_chunks_v1 SET bytes=zeroblob(length(bytes))",
            [],
        )
        .unwrap();
    drop(external);
    assert!(fetch_delta_to_file(
        &fixture.client,
        &fixture.delta,
        fixture.pins(),
        &[peer],
        limits(),
        &output,
    )
    .is_err());
    assert!(!output.exists());
    assert!(fixture
        .client
        .manifest(fixture.target.id())
        .unwrap()
        .is_none());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
