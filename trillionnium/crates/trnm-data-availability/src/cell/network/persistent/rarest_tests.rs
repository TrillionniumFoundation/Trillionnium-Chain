//! Real TCP controls for the explicit TCQ3/TCS3 profile.
use super::*;
use crate::cell::{CellCacheConfigV4, CellContextV1};
use std::{fs, path::PathBuf, sync::Arc, thread::JoinHandle};

fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 2 * 1_048_576,
        max_logical_bytes: 1_048_576,
        max_chunk_rows: 32,
        max_manifest_rows: 16,
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    origin: PathBuf,
    manifest: CellManifestV1,
    chunks: Vec<Vec<u8>>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let origin = dir.path().join("origin.sqlite");
        let chunks = vec![vec![7; 16_384], vec![8; 16_384], vec![9; 16_384]];
        let input = dir.path().join("weights");
        fs::write(&input, chunks.concat()).unwrap();
        let manifest = CellStoreV1::open(&origin, config())
            .unwrap()
            .pack_file(
                &input,
                CellContextV1 {
                    family: "persistent-rarest-v3".into(),
                    base: [1; 32],
                    parent: [2; 32],
                    tokenizer: [3; 32],
                    layout: [4; 32],
                    runtime: [5; 32],
                },
                16_384,
            )
            .unwrap();
        Self {
            dir,
            origin,
            manifest,
            chunks,
        }
    }

    fn cache(&self) -> CellStoreV1 {
        CellStoreV1::open(&self.dir.path().join("consumer.sqlite"), config()).unwrap()
    }

    fn wire_bytes(&self) -> u64 {
        self.manifest.encode().len() as u64 + self.manifest.size() + 5 * 9 + 1
    }
}

fn limits(requests: u64, bytes: u64) -> CellPersistentPeerLimitsV2 {
    CellPersistentPeerLimitsV2 {
        peer: CellPeerLimitsV1 {
            request_timeout: Duration::from_secs(2),
            overall_timeout: Duration::from_secs(5),
            max_cell_bytes: 1_048_576,
            parallelism: 1,
            max_connections: 1,
            max_response_bytes: bytes,
        },
        max_requests: requests,
        max_requests_per_connection: requests,
    }
}

struct Server {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<CellResultV1<CellPersistentServeReportV2>>>,
}

impl Server {
    fn start(path: &Path, requests: u64, bytes: u64, profile: WireProfile) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let path = path.to_owned();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            serve_cells_persistent_inner(
                &listener,
                &path,
                &shutdown,
                CellPersistentServeLimitsV2 {
                    serving: CellServeLimitsV1 {
                        request_timeout: Duration::from_secs(2),
                        overall_timeout: Duration::from_secs(5),
                        max_workers: 1,
                        max_connections: 1,
                        max_response_bytes: bytes,
                    },
                    max_requests: requests,
                    max_requests_per_connection: requests,
                },
                Some(&|| {
                    ready_tx
                        .send(())
                        .map_err(|_| CellErrorV1::Invalid("test ready receiver"))
                }),
                profile,
            )
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> CellPersistentServeReportV2 {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn response(magic: &[u8; 4], bytes: Option<&[u8]>) -> Vec<u8> {
    let mut wire = magic.to_vec();
    wire.push(u8::from(bytes.is_none()));
    wire.extend_from_slice(&(bytes.map_or(0, <[u8]>::len) as u32).to_be_bytes());
    if let Some(bytes) = bytes {
        wire.extend_from_slice(bytes);
    }
    wire
}

struct Peer {
    address: SocketAddr,
    calls: Arc<AtomicU64>,
    connections: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Peer {
    fn start(mut reply: impl FnMut(&[u8]) -> Option<Vec<u8>> + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let connections = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (count, dials, shutdown) = (calls.clone(), connections.clone(), stop.clone());
        let worker = thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(5);
            while !shutdown.load(Ordering::Relaxed) && Instant::now() < until {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("test accept: {error}"),
                };
                dials.fetch_add(1, Ordering::Relaxed);
                let deadline = until.min(Instant::now() + Duration::from_secs(2));
                for _ in 0..64 {
                    let mut query = [0; 43];
                    if read_deadline(&mut stream, &mut query[..37], deadline, None).is_err() {
                        break;
                    }
                    assert_eq!(&query[..4], b"TCQ3");
                    let length = if query[4] == 3 {
                        if read_deadline(&mut stream, &mut query[37..], deadline, None).is_err() {
                            break;
                        }
                        43
                    } else {
                        37
                    };
                    count.fetch_add(1, Ordering::Relaxed);
                    let Some(bytes) = reply(&query[..length]) else {
                        break;
                    };
                    if write_deadline(&mut stream, &bytes, deadline).is_err() {
                        break;
                    }
                }
            }
        });
        Self {
            address,
            calls,
            connections,
            stop,
            worker: Some(worker),
        }
    }

    fn supplying(fixture: &Fixture, held: u8, hint: u8, order: Arc<Mutex<Vec<usize>>>) -> Self {
        let manifest = fixture.manifest.clone();
        let chunks = fixture.chunks.clone();
        Self::start(move |query| match query[4] {
            1 => Some(response(b"TCS3", Some(&manifest.encode()))),
            3 => {
                assert_eq!(&query[5..37], &manifest.id());
                assert_eq!(&query[37..], &[0, 0, 0, 0, 0, 3]);
                Some(response(b"TCS3", Some(&[hint])))
            }
            2 => {
                let index = manifest
                    .chunks()
                    .iter()
                    .position(|chunk| chunk.sha256.as_slice() == &query[5..])
                    .unwrap();
                order.lock().unwrap().push(index);
                Some(response(
                    b"TCS3",
                    (held & (1 << index) != 0).then_some(chunks[index].as_slice()),
                ))
            }
            _ => panic!("unexpected test request"),
        })
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

#[test]
fn v3_real_server_reuses_one_connection_for_manifest_inventory_and_verified_payload() {
    let fixture = Fixture::new();
    let server = Server::start(
        &fixture.origin,
        5,
        fixture.wire_bytes(),
        WireProfile::RarestFirstV3,
    );
    let output = fixture.dir.path().join("complete.weights");
    let (_, report) = fetch_cell_persistent_rarest_first_to_file(
        &fixture.cache(),
        fixture.manifest.id(),
        &[server.address],
        limits(5, fixture.wire_bytes()),
        &output,
    )
    .unwrap();
    assert_eq!(fs::read(output).unwrap(), fixture.chunks.concat());
    assert_eq!(report.request_attempts, 5);
    assert_eq!(report.fetch.connection_attempts, 1);
    assert_eq!(report.fetch.received_response_bytes, fixture.wire_bytes());
    assert_eq!(report.fetch.downloaded_chunks, 3);
    assert_eq!(report.fetch.rejected_responses, 0);
    let served = server.finish();
    assert_eq!(served.request_attempts, 5);
    assert_eq!(served.serving.completed_requests, 5);
    assert_eq!(served.serving.accepted_connections, 1);
    assert_eq!(served.serving.sent_response_bytes, fixture.wire_bytes());
}

#[test]
fn v3_partial_providers_schedule_rarest_chunks_first_with_two_reused_connections() {
    let fixture = Fixture::new();
    let order = Arc::new(Mutex::new(Vec::new()));
    let first = Peer::supplying(&fixture, 3, 3, order.clone());
    let second = Peer::supplying(&fixture, 5, 5, order.clone());
    let cache = fixture.cache();
    cache
        .put_manifest(fixture.manifest.id(), &fixture.manifest.encode())
        .unwrap();
    let wire_bytes = fixture.manifest.size() + 3 * 9 + 2 * 10;
    let mut limit = limits(5, wire_bytes);
    limit.peer.max_connections = 2;
    let output = fixture.dir.path().join("complete.weights");
    let (_, report) = fetch_cell_persistent_rarest_first_to_file(
        &cache,
        fixture.manifest.id(),
        &[first.address, second.address],
        limit,
        &output,
    )
    .unwrap();
    assert_eq!(*order.lock().unwrap(), [1, 2, 0]);
    assert_eq!(fs::read(output).unwrap(), fixture.chunks.concat());
    assert_eq!(report.request_attempts, 5);
    assert_eq!(report.fetch.connection_attempts, 2);
    assert_eq!(report.fetch.received_response_bytes, wire_bytes);
    assert_eq!(report.fetch.supplying_peers.len(), 2);
    assert_eq!(report.fetch.rejected_responses, 0);
    assert_eq!(
        first.calls.load(Ordering::Relaxed) + second.calls.load(Ordering::Relaxed),
        5
    );
    assert_eq!(first.connections.load(Ordering::Relaxed), 1);
    assert_eq!(second.connections.load(Ordering::Relaxed), 1);
}

#[test]
fn v3_empty_inventory_is_a_hint_and_cannot_hide_real_verified_chunks() {
    let fixture = Fixture::new();
    let peer = Peer::supplying(&fixture, 7, 0, Arc::default());
    let (_, report) = fetch_cell_persistent_rarest_first(
        &fixture.cache(),
        fixture.manifest.id(),
        &[peer.address],
        limits(5, fixture.wire_bytes()),
    )
    .unwrap();
    assert_eq!(report.fetch.downloaded_chunks, 3);
    assert_eq!(report.fetch.rejected_responses, 0);
    assert_eq!(report.request_attempts, 5);
    assert_eq!(report.fetch.connection_attempts, 1);
}

#[test]
fn v3_real_inventory_crosses_page_256_and_reuses_its_reservation_for_tail_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("paged-origin.sqlite");
    let input = dir.path().join("paged-weights");
    // A bounded protocol fixture, not either historical model cohort.
    let chunks: Vec<Vec<u8>> = (0..269_u32)
        .map(|index| {
            let mut bytes = vec![0x5a; 16_384];
            bytes[..4].copy_from_slice(&index.to_le_bytes());
            bytes
        })
        .collect();
    fs::write(&input, chunks.concat()).unwrap();
    let store = CellStoreV1::open(
        &path,
        CellCacheConfigV4 {
            max_database_bytes: 16 * 1_048_576,
            max_logical_bytes: 8 * 1_048_576,
            max_chunk_rows: 512,
            max_manifest_rows: 16,
        },
    )
    .unwrap();
    let manifest = store
        .pack_file(
            &input,
            CellContextV1 {
                family: "persistent-rarest-pages".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            },
            16_384,
        )
        .unwrap();
    assert_eq!(manifest.chunks().len(), 269);
    drop(store);
    // First page has 32 bitmap bytes; the thirteen-slot tail has two.
    let inventory_bytes = (9 + 32) + (9 + 2);
    let wire_bytes = inventory_bytes + 9 + 16_384;
    let server = Server::start(&path, 3, wire_bytes, WireProfile::RarestFirstV3);
    let pool = ConnectionPool::new_rarest_first(&[server.address], limits(3, wire_bytes));
    let connections = AtomicU64::new(1);
    let responses = ResponseBudget::new(wire_bytes);
    let context = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: Instant::now() + Duration::from_secs(5),
        requests_left: &connections,
        responses: &responses,
    };
    let missing: Vec<_> = manifest.chunks().iter().cloned().enumerate().collect();
    let (observed, rejected) =
        availability::observe_via(&manifest, &missing, &[server.address], &context, &pool).unwrap();
    assert_eq!(observed, vec![1; 269]);
    assert_eq!(rejected, 0);
    assert_eq!(responses.received().unwrap(), inventory_bytes);
    assert_eq!(pool.requests_left.load(Ordering::Relaxed), 1);
    let (tail, _, rejected) = download_chunk_via(
        &manifest.chunks()[268],
        268,
        &[server.address],
        &context,
        1,
        &pool,
    )
    .unwrap();
    assert_eq!(tail, chunks[268]);
    assert_eq!(rejected, 0);
    assert_eq!(connections.load(Ordering::Relaxed), 0);
    assert_eq!(pool.requests_left.load(Ordering::Relaxed), 0);
    assert_eq!(responses.received().unwrap(), wire_bytes);
    drop(pool);
    let served = server.finish();
    assert_eq!(served.serving.accepted_connections, 1);
    assert_eq!(served.serving.completed_requests, 3);
    assert_eq!(served.serving.sent_response_bytes, wire_bytes);
}

#[test]
fn v3_inventory_frame_exhaustion_keeps_verified_prefix_for_explicit_resume() {
    let fixture = Fixture::new();
    let cache = fixture.cache();
    let output = fixture.dir.path().join("complete.weights");
    let server = Server::start(
        &fixture.origin,
        3,
        fixture.wire_bytes(),
        WireProfile::RarestFirstV3,
    );
    assert!(fetch_cell_persistent_rarest_first_to_file(
        &cache,
        fixture.manifest.id(),
        &[server.address],
        limits(3, fixture.wire_bytes()),
        &output,
    )
    .is_err());
    assert!(!output.exists());
    assert!(cache
        .chunk(fixture.manifest.chunks()[0].sha256)
        .unwrap()
        .is_some());
    assert!(cache
        .chunk(fixture.manifest.chunks()[1].sha256)
        .unwrap()
        .is_none());
    let served = server.finish();
    assert_eq!(served.request_attempts, 3);
    assert_eq!(served.serving.completed_requests, 3);
    assert_eq!(served.serving.accepted_connections, 1);
    let resume_bytes = 2 * (16_384 + 9) + 10;
    let server = Server::start(&fixture.origin, 3, resume_bytes, WireProfile::RarestFirstV3);
    let (_, report) = fetch_cell_persistent_rarest_first_to_file(
        &cache,
        fixture.manifest.id(),
        &[server.address],
        limits(3, resume_bytes),
        &output,
    )
    .unwrap();
    assert_eq!(report.request_attempts, 3);
    assert_eq!(report.fetch.cached_chunks, 1);
    assert_eq!(report.fetch.downloaded_chunks, 2);
    assert_eq!(report.fetch.received_response_bytes, resume_bytes);
    assert_eq!(fs::read(output).unwrap(), fixture.chunks.concat());
    assert_eq!(server.finish().serving.completed_requests, 3);
}

#[test]
fn v3_inventory_spends_original_bytes_and_denies_a_fresh_payload_allowance() {
    let fixture = Fixture::new();
    let peer = Peer::supplying(&fixture, 7, 7, Arc::default());
    let pool = ConnectionPool::new_rarest_first(&[peer.address], limits(3, 10));
    let connections = AtomicU64::new(1);
    let responses = ResponseBudget::new(10);
    let context = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: Instant::now() + Duration::from_secs(5),
        requests_left: &connections,
        responses: &responses,
    };
    assert_eq!(
        pool.inventory_page(peer.address, fixture.manifest.id(), 0, 3, &context)
            .unwrap(),
        [7]
    );
    assert_eq!(responses.received().unwrap(), 10);
    assert!(pool
        .request(
            peer.address,
            2,
            fixture.manifest.chunks()[0].sha256,
            16_384,
            &context
        )
        .0
        .is_err());
    assert_eq!(pool.requests_left.load(Ordering::Relaxed), 2);
    assert_eq!(connections.load(Ordering::Relaxed), 0);
    assert_eq!(peer.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn v3_wrong_magic_or_noncanonical_inventory_quarantines_without_fallback() {
    for malformed in [
        response(b"TCS2", Some(&[7])),
        response(b"TCS3", Some(&[0x80])),
        response(b"TCS3", Some(&[])),
        response(b"TCS3", Some(&[7, 0])),
    ] {
        let peer = Peer::start(move |_| Some(malformed.clone()));
        let pool = ConnectionPool::new_rarest_first(&[peer.address], limits(3, 1024));
        let connections = AtomicU64::new(1);
        let responses = ResponseBudget::new(1024);
        let context = RequestContext {
            cancelled: None,
            timeout: Duration::from_secs(2),
            overall: Instant::now() + Duration::from_secs(5),
            requests_left: &connections,
            responses: &responses,
        };
        assert!(pool
            .inventory_page(peer.address, [1; 32], 0, 3, &context)
            .is_err());
        assert!(responses.is_quarantined(peer.address).unwrap());
        assert!(pool
            .request(peer.address, 2, [2; 32], 1, &context)
            .0
            .is_err());
        assert_eq!(pool.requests_left.load(Ordering::Relaxed), 2);
        assert_eq!(connections.load(Ordering::Relaxed), 0);
        assert_eq!(peer.calls.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn v3_claimed_inventory_never_admits_a_bad_chunk_or_partial_output() {
    let fixture = Fixture::new();
    let cache = fixture.cache();
    cache
        .put_manifest(fixture.manifest.id(), &fixture.manifest.encode())
        .unwrap();
    let peer = Peer::start(|query| {
        Some(response(
            b"TCS3",
            Some(if query[4] == 3 { &[7] } else { &[0; 16_384] }),
        ))
    });
    let output = fixture.dir.path().join("must-not-exist");
    assert!(fetch_cell_persistent_rarest_first_to_file(
        &cache,
        fixture.manifest.id(),
        &[peer.address],
        limits(5, 100_000),
        &output,
    )
    .is_err());
    assert!(!output.exists());
    for chunk in fixture.manifest.chunks() {
        assert!(cache.chunk(chunk.sha256).unwrap().is_none());
    }
    assert_eq!(peer.calls.load(Ordering::Relaxed), 2);
    assert_eq!(peer.connections.load(Ordering::Relaxed), 1);
}

#[test]
fn v3_partial_inventory_drops_connection_without_implicit_frame_retry() {
    let peer = Peer::start(|_| {
        let mut truncated = response(b"TCS3", Some(&[1]));
        truncated.pop();
        Some(truncated)
    });
    let mut limit = limits(3, 1024);
    limit.peer.request_timeout = Duration::from_millis(100);
    let pool = ConnectionPool::new_rarest_first(&[peer.address], limit);
    let connections = AtomicU64::new(1);
    let responses = ResponseBudget::new(1024);
    let context = RequestContext {
        cancelled: None,
        timeout: limit.peer.request_timeout,
        overall: Instant::now() + Duration::from_secs(5),
        requests_left: &connections,
        responses: &responses,
    };
    assert!(pool
        .inventory_page(peer.address, [1; 32], 0, 1, &context)
        .is_err());
    assert!(!responses.is_quarantined(peer.address).unwrap());
    assert_eq!(responses.received().unwrap(), 9);
    assert_eq!(pool.requests_left.load(Ordering::Relaxed), 2);
    assert!(pool.peers[0].1.lock().unwrap().is_none());
    assert!(pool
        .inventory_page(peer.address, [1; 32], 0, 1, &context)
        .is_err());
    assert_eq!(connections.load(Ordering::Relaxed), 0);
    assert_eq!(pool.requests_left.load(Ordering::Relaxed), 1);
    assert_eq!(peer.calls.load(Ordering::Relaxed), 1);
    assert_eq!(peer.connections.load(Ordering::Relaxed), 1);
}

#[test]
fn v3_cancellation_after_inventory_remains_terminal_without_a_payload_frame() {
    let fixture = Fixture::new();
    let peer = Peer::supplying(&fixture, 7, 7, Arc::default());
    let pool = ConnectionPool::new_rarest_first(&[peer.address], limits(3, 100_000));
    let connections = AtomicU64::new(1);
    let responses = ResponseBudget::new(100_000);
    let cancelled = AtomicBool::new(false);
    let context = RequestContext {
        cancelled: Some(&cancelled),
        timeout: Duration::from_secs(2),
        overall: Instant::now() + Duration::from_secs(5),
        requests_left: &connections,
        responses: &responses,
    };
    pool.inventory_page(peer.address, fixture.manifest.id(), 0, 3, &context)
        .unwrap();
    cancelled.store(true, Ordering::Release);
    assert!(pool
        .request(
            peer.address,
            2,
            fixture.manifest.chunks()[0].sha256,
            16_384,
            &context
        )
        .0
        .is_err());
    cancelled.store(false, Ordering::Release);
    assert!(pool
        .inventory_page(peer.address, fixture.manifest.id(), 0, 3, &context)
        .is_err());
    assert_eq!(pool.requests_left.load(Ordering::Relaxed), 2);
    assert_eq!(responses.received().unwrap(), 10);
    assert_eq!(peer.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn v3_inventory_and_payload_keep_original_connection_and_session_deadlines() {
    let fixture = Fixture::new();
    let peer = Peer::supplying(&fixture, 7, 7, Arc::default());
    let pool = ConnectionPool::new_rarest_first(&[peer.address], limits(4, 100_000));
    let connections = AtomicU64::new(1);
    let responses = ResponseBudget::new(100_000);
    let context = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: Instant::now() + Duration::from_secs(5),
        requests_left: &connections,
        responses: &responses,
    };
    pool.inventory_page(peer.address, fixture.manifest.id(), 0, 3, &context)
        .unwrap();
    let original = pool.peers[0].1.lock().unwrap().as_ref().unwrap().deadline;
    assert_eq!(
        pool.request(
            peer.address,
            2,
            fixture.manifest.chunks()[0].sha256,
            16_384,
            &context
        )
        .0
        .unwrap(),
        fixture.chunks[0]
    );
    assert_eq!(
        pool.peers[0].1.lock().unwrap().as_ref().unwrap().deadline,
        original
    );
    assert!(original < context.overall);
    let expired = RequestContext {
        overall: Instant::now() - Duration::from_millis(1),
        ..context
    };
    assert!(pool
        .inventory_page(peer.address, fixture.manifest.id(), 0, 3, &expired)
        .is_err());
    assert!(pool
        .request(
            peer.address,
            2,
            fixture.manifest.chunks()[1].sha256,
            16_384,
            &expired
        )
        .0
        .is_err());
    assert_eq!(pool.requests_left.load(Ordering::Relaxed), 2);
    assert_eq!(connections.load(Ordering::Relaxed), 0);
    assert_eq!(responses.received().unwrap(), 10 + 9 + 16_384);
    assert_eq!(peer.calls.load(Ordering::Relaxed), 2);
}

#[test]
fn v3_server_rejects_old_namespaces_and_invalid_inventory_before_object_bytes() {
    let fixture = Fixture::new();
    for (magic, start, count) in [
        (*b"TCQ1", 0_u32, 3_u16),
        (*b"TCQ2", 0, 3),
        (*b"TCI1", 0, 3),
        (*b"TCQ3", 0, 0),
        (*b"TCQ3", 0, 257),
        (*b"TCQ3", 3, 1),
        (*b"TCQ3", u32::MAX, 1),
    ] {
        let server = Server::start(&fixture.origin, 1, 1024, WireProfile::RarestFirstV3);
        let mut stream = TcpStream::connect(server.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut query = magic.to_vec();
        query.push(3);
        query.extend_from_slice(&fixture.manifest.id());
        query.extend_from_slice(&start.to_be_bytes());
        query.extend_from_slice(&count.to_be_bytes());
        stream.write_all(&query).unwrap();
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        assert!(received.is_empty());
        drop(stream);
        let report = server.finish();
        assert_eq!(report.request_attempts, 1);
        assert_eq!(report.serving.completed_requests, 0);
        assert_eq!(report.serving.sent_response_bytes, 0);
    }
    let server = Server::start(&fixture.origin, 1, 1024, WireProfile::OrderedV2);
    let mut stream = TcpStream::connect(server.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut query = b"TCQ3".to_vec();
    query.push(1);
    query.extend_from_slice(&fixture.manifest.id());
    stream.write_all(&query).unwrap();
    let mut received = Vec::new();
    let _ = stream.read_to_end(&mut received);
    assert!(received.is_empty());
    drop(stream);
    assert_eq!(server.finish().serving.completed_requests, 0);
}

#[test]
fn v3_invalid_local_inventory_range_and_v2_profile_cannot_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let connections = AtomicU64::new(1);
    let responses = ResponseBudget::new(1024);
    let context = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: Instant::now() + Duration::from_secs(5),
        requests_left: &connections,
        responses: &responses,
    };
    for profile in [WireProfile::OrderedV2, WireProfile::RarestFirstV3] {
        let pool = ConnectionPool::with_profile(&[address], limits(3, 1024), profile);
        let counts: &[usize] = if profile == WireProfile::OrderedV2 {
            &[1]
        } else {
            &[0, 257]
        };
        for count in counts {
            assert!(pool
                .inventory_page(address, [1; 32], 0, *count, &context)
                .is_err());
        }
        assert_eq!(pool.requests_left.load(Ordering::Relaxed), 3);
    }
    assert_eq!(connections.load(Ordering::Relaxed), 1);
    assert_eq!(responses.received().unwrap(), 0);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
