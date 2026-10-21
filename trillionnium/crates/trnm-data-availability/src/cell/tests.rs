use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use super::*;

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "native-test-v1".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}

fn limits() -> CellPeerLimitsV1 {
    CellPeerLimitsV1 {
        request_timeout: Duration::from_secs(2),
        overall_timeout: Duration::from_secs(30),
        max_cell_bytes: 1_048_576,
        parallelism: 2,
        max_connections: 1000,
        max_response_bytes: 4 * 1_048_576,
    }
}

struct Peer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<CellResultV1<u64>>>,
}

impl Peer {
    fn start(path: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let path = path.to_owned();
        let handle = thread::spawn(move || {
            let store = CellStoreV1::open(&path)?;
            serve_cells(&listener, &store, &stop, limits())
        });
        Self {
            address,
            shutdown,
            handle: Some(handle),
        }
    }

    fn stop(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap().unwrap();
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn payload() -> Vec<u8> {
    (0_u32..4097)
        .flat_map(|i| <[u8; 32]>::from(Sha256::digest(i.to_be_bytes())))
        .collect()
}

#[test]
fn origin_offline_independent_replicas_multisource_and_corrupt_cache_repair() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    let bytes = payload();
    fs::write(&input, &bytes).unwrap();
    let origin_path = directory.path().join("origin.sqlite");
    let origin = CellStoreV1::open(&origin_path).unwrap();
    let manifest = origin.pack_file(&input, context(), 16_384).unwrap();
    let publisher = Peer::start(&origin_path);
    let a_path = directory.path().join("a.sqlite");
    let b_path = directory.path().join("b.sqlite");
    for path in [&a_path, &b_path] {
        let replica = CellStoreV1::open(path).unwrap();
        let (received, report) =
            fetch_cell(&replica, manifest.id(), &[publisher.address], limits()).unwrap();
        assert_eq!(received, manifest);
        assert_eq!(report.downloaded_bytes, bytes.len() as u64);
        assert_eq!(
            report.received_response_bytes,
            bytes.len() as u64
                + manifest.encode().len() as u64
                + 9 * (manifest.chunks().len() as u64 + 1)
        );
        replica.verify_complete(&received).unwrap();
    }
    publisher.stop();
    drop(origin);
    fs::remove_file(&input).unwrap();
    fs::remove_file(&origin_path).unwrap();
    let a = Peer::start(&a_path);
    let b = Peer::start(&b_path);
    let consumer_path = directory.path().join("consumer.sqlite");
    let consumer = CellStoreV1::open(&consumer_path).unwrap();
    let (_, report) =
        fetch_cell(&consumer, manifest.id(), &[a.address, b.address], limits()).unwrap();
    assert_eq!(report.supplying_peers.len(), 2);
    let output = directory.path().join("model.weights");
    consumer.materialize(&manifest, &output).unwrap();
    assert_eq!(fs::read(&output).unwrap(), bytes);

    let external = Connection::open(&consumer_path).unwrap();
    let first = &manifest.chunks()[0];
    external
        .execute(
            "UPDATE cell_chunks_v1 SET bytes = ?1 WHERE hash = ?2",
            params![vec![0_u8; first.size as usize], first.sha256.as_slice()],
        )
        .unwrap();
    let (_, report) =
        fetch_cell(&consumer, manifest.id(), &[a.address, b.address], limits()).unwrap();
    assert_eq!(report.downloaded_chunks, 1);
    assert_eq!(report.cached_chunks, manifest.chunks().len() - 1);
    assert!(consumer.materialize(&manifest, &output).is_err());
    assert_eq!(fs::read(&output).unwrap(), bytes);
    let (_, cached) = fetch_cell(&consumer, manifest.id(), &[], limits()).unwrap();
    assert_eq!(cached.downloaded_chunks, 0);
    assert_eq!(cached.received_response_bytes, 0);
    a.stop();
    b.stop();
}

#[test]
fn missing_chunk_never_publishes_partial_payload_and_verified_cache_resumes() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    fs::write(&input, payload()).unwrap();
    let origin = CellStoreV1::open(&directory.path().join("origin")).unwrap();
    let manifest = origin.pack_file(&input, context(), 16_384).unwrap();
    let partial = CellStoreV1::open(&directory.path().join("partial")).unwrap();
    partial
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    for chunk in &manifest.chunks()[..manifest.chunks().len() - 1] {
        partial
            .put_chunk(chunk, &origin.chunk(chunk.sha256).unwrap().unwrap())
            .unwrap();
    }
    let output = directory.path().join("must-not-exist");
    assert!(fetch_cell(&partial, manifest.id(), &[], limits()).is_err());
    assert!(partial.materialize(&manifest, &output).is_err());
    assert!(!output.exists());
    let publisher = Peer::start(&directory.path().join("origin"));
    let (_, report) = fetch_cell(&partial, manifest.id(), &[publisher.address], limits()).unwrap();
    assert_eq!(report.downloaded_chunks, 1);
    partial.materialize(&manifest, &output).unwrap();
    assert_eq!(fs::read(output).unwrap(), payload());
    publisher.stop();
}

#[test]
fn wrong_pins_context_chunks_and_noncanonical_manifests_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    fs::write(&input, payload()).unwrap();
    let store = CellStoreV1::open(&directory.path().join("store")).unwrap();
    let manifest = store.pack_file(&input, context(), 16_384).unwrap();
    assert_eq!(
        CellManifestV1::decode(&manifest.encode()).unwrap(),
        manifest
    );
    assert!(store.put_manifest([0; 32], &manifest.encode()).is_err());
    let mut another = context();
    another.parent = [9; 32];
    let changed = store.pack_file(&input, another, 16_384).unwrap();
    assert_ne!(changed.id(), manifest.id());
    assert_eq!(changed.payload_sha256(), manifest.payload_sha256());
    let mut extra = manifest.encode();
    extra.push(0);
    assert!(CellManifestV1::decode(&extra).is_err());
    for end in 0..manifest.encode().len() {
        assert!(CellManifestV1::decode(&manifest.encode()[..end]).is_err());
    }
    assert!(store
        .put_chunk(&manifest.chunks()[0], &[0; 16_384])
        .is_err());
    let mut budget = limits();
    budget.max_cell_bytes = manifest.size() - 1;
    assert!(fetch_cell(&store, manifest.id(), &[], budget).is_err());
    assert!(parse_digest(&"A".repeat(64)).is_err());
    assert_eq!(
        parse_digest(&digest_hex(manifest.id())).unwrap(),
        manifest.id()
    );
}

#[test]
fn foreign_database_is_not_repurposed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ledger.sqlite");
    let foreign = Connection::open(&path).unwrap();
    foreign.execute_batch("CREATE TABLE existing_ledger (value INTEGER); INSERT INTO existing_ledger VALUES (42);").unwrap();
    assert!(CellStoreV1::open(&path).is_err());
    assert_eq!(
        foreign
            .query_row("SELECT value FROM existing_ledger", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        42
    );
}

fn wrong_peer(bytes: Vec<u8>, declared: u32) -> (SocketAddr, JoinHandle<()>) {
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut query = [0; 37];
        stream.read_exact(&mut query).unwrap();
        let mut header = b"TCS1\0".to_vec();
        header.extend_from_slice(&declared.to_be_bytes());
        stream.write_all(&header).unwrap();
        let _ = stream.write_all(&bytes);
    });
    (address, handle)
}

#[test]
fn corrupt_network_supplier_is_rejected_and_honest_peer_completes_same_pin() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("model");
    fs::write(&input, vec![7; 8192]).unwrap();
    let origin_path = directory.path().join("origin");
    let origin = CellStoreV1::open(&origin_path).unwrap();
    let manifest = origin.pack_file(&input, context(), 16_384).unwrap();
    let receiver = CellStoreV1::open(&directory.path().join("receiver")).unwrap();
    receiver
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    let honest = Peer::start(&origin_path);
    let (bad, thread) = wrong_peer(vec![0; 8192], 8192);
    let (_, report) =
        fetch_cell(&receiver, manifest.id(), &[bad, honest.address], limits()).unwrap();
    assert_eq!(report.rejected_responses, 1);
    assert_eq!(report.connection_attempts, 2);
    assert_eq!(report.downloaded_bytes, 8192);
    assert_eq!(report.received_response_bytes, 2 * (8192 + 9));
    assert_eq!(report.supplying_peers, [honest.address].into());
    receiver.verify_complete(&manifest).unwrap();
    thread.join().unwrap();
    honest.stop();

    let empty = CellStoreV1::open(&directory.path().join("empty")).unwrap();
    let (oversized, thread) = wrong_peer(Vec::new(), u32::MAX);
    assert!(fetch_cell(&empty, manifest.id(), &[oversized], limits()).is_err());
    assert!(empty.manifest(manifest.id()).unwrap().is_none());
    thread.join().unwrap();
}

#[test]
fn exhausted_transport_budget_keeps_verified_chunks_for_retry() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    fs::write(&input, payload()).unwrap();
    let path = directory.path().join("origin");
    let origin = CellStoreV1::open(&path).unwrap();
    let manifest = origin.pack_file(&input, context(), 16_384).unwrap();
    let publisher = Peer::start(&path);
    let receiver = CellStoreV1::open(&directory.path().join("receiver")).unwrap();
    let mut bounded = limits();
    bounded.parallelism = 1;
    bounded.max_connections = 2;
    assert!(fetch_cell(&receiver, manifest.id(), &[publisher.address], bounded).is_err());
    assert!(receiver.manifest(manifest.id()).unwrap().is_some());
    assert!(receiver
        .chunk(manifest.chunks()[0].sha256)
        .unwrap()
        .is_some());
    assert!(receiver.verify_complete(&manifest).is_err());
    let (_, report) = fetch_cell(&receiver, manifest.id(), &[publisher.address], limits()).unwrap();
    assert_eq!(report.cached_chunks, 1);
    assert_eq!(
        report.downloaded_chunks + report.cached_chunks,
        manifest.chunks().len()
    );
    publisher.stop();
}

#[test]
fn parallel_fetch_uses_exact_response_budget_and_cache_needs_no_network_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    let bytes = payload();
    fs::write(&input, &bytes).unwrap();
    let path = directory.path().join("origin");
    let origin = CellStoreV1::open(&path).unwrap();
    let manifest = origin.pack_file(&input, context(), 16_384).unwrap();
    let publisher = Peer::start(&path);
    let receiver = CellStoreV1::open(&directory.path().join("receiver")).unwrap();
    let mut bounded = limits();
    bounded.parallelism = 4;
    bounded.max_response_bytes = bytes.len() as u64
        + manifest.encode().len() as u64
        + 9 * (manifest.chunks().len() as u64 + 1);
    let (_, report) = fetch_cell(&receiver, manifest.id(), &[publisher.address], bounded).unwrap();
    assert_eq!(report.received_response_bytes, bounded.max_response_bytes);
    assert_eq!(report.downloaded_bytes, bytes.len() as u64);
    bounded.max_response_bytes = 0;
    let (_, cached) = fetch_cell(&receiver, manifest.id(), &[], bounded).unwrap();
    assert_eq!(cached.received_response_bytes, 0);
    assert_eq!(cached.connection_attempts, 0);
    assert_eq!(cached.downloaded_bytes, 0);
    assert_eq!(cached.cached_chunks, manifest.chunks().len());
    publisher.stop();
}

#[test]
fn corrupt_response_exhausts_bytes_before_honest_fallback_and_explicit_retry_recovers() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("model");
    fs::write(&input, vec![7; 8192]).unwrap();
    let path = directory.path().join("origin");
    let origin = CellStoreV1::open(&path).unwrap();
    let manifest = origin.pack_file(&input, context(), 16_384).unwrap();
    let receiver = CellStoreV1::open(&directory.path().join("receiver")).unwrap();
    receiver
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    let honest = Peer::start(&path);
    let (bad, handle) = wrong_peer(vec![0; 8192], 8192);
    let mut bounded = limits();
    bounded.max_response_bytes = 8192 + 9;
    let failure =
        fetch_cell(&receiver, manifest.id(), &[bad, honest.address], bounded).unwrap_err();
    assert!(matches!(
        failure,
        CellErrorV1::ResponseByteBudgetExhausted {
            received_response_bytes: 8201,
            max_response_bytes: 8201,
        }
    ));
    handle.join().unwrap();
    assert!(receiver
        .chunk(manifest.chunks()[0].sha256)
        .unwrap()
        .is_none());
    assert!(receiver.verify_complete(&manifest).is_err());
    let output = directory.path().join("must-not-exist");
    assert!(receiver.materialize(&manifest, &output).is_err());
    assert!(!output.exists());
    let (_, report) = fetch_cell(&receiver, manifest.id(), &[honest.address], bounded).unwrap();
    assert_eq!(report.downloaded_bytes, 8192);
    assert_eq!(report.received_response_bytes, bounded.max_response_bytes);
    receiver.verify_complete(&manifest).unwrap();
    honest.stop();
}

#[test]
fn truncated_body_and_rejected_header_charge_only_received_bytes_before_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("model");
    fs::write(&input, vec![7; 8192]).unwrap();
    let path = directory.path().join("origin");
    let origin = CellStoreV1::open(&path).unwrap();
    let manifest = origin.pack_file(&input, context(), 16_384).unwrap();
    let honest = Peer::start(&path);
    for (body, declared) in [(vec![7; 137], 8192), (Vec::new(), u32::MAX)] {
        let rejected_bytes = body.len() as u64 + 9;
        let receiver =
            CellStoreV1::open(&directory.path().join(format!("receiver-{declared}"))).unwrap();
        receiver
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
        let (bad, handle) = wrong_peer(body, declared);
        let mut bounded = limits();
        bounded.max_response_bytes = rejected_bytes + 8192 + 9;
        let (_, report) =
            fetch_cell(&receiver, manifest.id(), &[bad, honest.address], bounded).unwrap();
        assert_eq!(report.received_response_bytes, bounded.max_response_bytes);
        assert_eq!(report.downloaded_bytes, 8192);
        assert_eq!(report.rejected_responses, 1);
        assert_eq!(report.connection_attempts, 2);
        receiver.verify_complete(&manifest).unwrap();
        handle.join().unwrap();
    }
    honest.stop();
}

#[test]
fn manifest_header_and_body_obey_response_budget_before_cache_publication() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("model");
    fs::write(&input, vec![7; 8192]).unwrap();
    let path = directory.path().join("origin");
    let origin = CellStoreV1::open(&path).unwrap();
    let manifest = origin.pack_file(&input, context(), 16_384).unwrap();
    let publisher = Peer::start(&path);
    for maximum in [5, manifest.encode().len() as u64 + 8] {
        let receiver =
            CellStoreV1::open(&directory.path().join(format!("receiver-{maximum}"))).unwrap();
        let mut bounded = limits();
        bounded.max_response_bytes = maximum;
        let failure =
            fetch_cell(&receiver, manifest.id(), &[publisher.address], bounded).unwrap_err();
        match failure {
            CellErrorV1::ResponseByteBudgetExhausted {
                received_response_bytes,
                max_response_bytes,
            } => {
                assert_eq!(received_response_bytes, maximum);
                assert_eq!(max_response_bytes, maximum);
            }
            other => panic!("expected response budget failure, got {other}"),
        }
        assert!(receiver.manifest(manifest.id()).unwrap().is_none());
    }
    assert!(CellPeerLimitsV1::default_response_byte_budget(u64::MAX, 1).is_err());
    assert!(CellPeerLimitsV1::default_response_byte_budget(1, u64::MAX).is_err());
    let mut invalid = limits();
    invalid.max_response_bytes = u64::MAX;
    assert!(fetch_cell(&origin, manifest.id(), &[], invalid).is_err());
    publisher.stop();
}

#[test]
fn slow_response_cannot_extend_absolute_deadline_and_honest_peer_keeps_pin() {
    use std::{
        io::{Read, Write},
        sync::atomic::AtomicUsize,
        time::Instant,
    };

    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("model");
    let bytes = vec![7; 8192];
    fs::write(&input, &bytes).unwrap();
    let origin_path = directory.path().join("origin");
    let origin = CellStoreV1::open(&origin_path).unwrap();
    let manifest = origin.pack_file(&input, context(), 16_384).unwrap();
    let receiver = CellStoreV1::open(&directory.path().join("receiver")).unwrap();
    receiver
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    let honest = Peer::start(&origin_path);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let slow_address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicUsize::new(0));
    let slow_stop = stop.clone();
    let slow_sent = sent.clone();
    let expected_chunk = manifest.chunks()[0].sha256;
    let slow = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut query = [0; 37];
        stream.read_exact(&mut query).unwrap();
        assert_eq!(&query[..5], b"TCQ1\x02");
        assert_eq!(&query[5..], &expected_chunk);
        let mut header = b"TCS1\0".to_vec();
        header.extend_from_slice(&8192_u32.to_be_bytes());
        stream.write_all(&header).unwrap();
        // Every byte is plausible, and gaps are shorter than the original
        // request deadline. Restarting an idle timeout after each read would
        // keep this connection alive beyond the complete fetch budget.
        let end = Instant::now() + Duration::from_secs(3);
        while !slow_stop.load(Ordering::Relaxed) && Instant::now() < end {
            if stream.write_all(&[7]).is_err() {
                break;
            }
            slow_sent.fetch_add(1, Ordering::Relaxed);
            thread::sleep(Duration::from_millis(20));
        }
    });

    let mut bounded = limits();
    bounded.request_timeout = Duration::from_millis(100);
    bounded.overall_timeout = Duration::from_secs(2);
    bounded.parallelism = 1;
    bounded.max_connections = 2;
    let started = Instant::now();
    let fetched = fetch_cell(
        &receiver,
        manifest.id(),
        &[slow_address, honest.address],
        bounded,
    );
    let elapsed = started.elapsed();
    stop.store(true, Ordering::Relaxed);
    slow.join().unwrap();
    let (received, report) = fetched.unwrap();
    assert_eq!(received, manifest);
    assert!(sent.load(Ordering::Relaxed) >= 2);
    // Ten times the configured per-connection bound leaves scheduling margin;
    // this is a liveness regression, not a throughput or latency measurement.
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    assert_eq!(report.connection_attempts, 2);
    assert_eq!(report.rejected_responses, 1);
    assert_eq!(report.supplying_peers, [honest.address].into());
    assert_eq!(report.downloaded_bytes, bytes.len() as u64);
    let output = directory.path().join("complete.weights");
    receiver.materialize(&received, &output).unwrap();
    assert_eq!(fs::read(output).unwrap(), bytes);
    honest.stop();
}
