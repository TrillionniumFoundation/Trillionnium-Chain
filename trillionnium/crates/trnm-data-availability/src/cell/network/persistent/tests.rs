use super::*;
use crate::cell::{CellCacheConfigV4, CellContextV1};
use std::{fs, path::PathBuf, sync::Arc, thread::JoinHandle};

fn cache_config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 2 * 1_048_576,
        max_logical_bytes: 1_048_576,
        max_chunk_rows: 16,
        max_manifest_rows: 16,
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf, CellManifestV1, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let bytes = [vec![7; 16_384], vec![8; 16_384]].concat();
    let input = dir.path().join("source.weights");
    fs::write(&input, &bytes).unwrap();
    let path = dir.path().join("source.sqlite");
    let cache = CellStoreV1::open(&path, cache_config()).unwrap();
    let manifest = cache
        .pack_file(
            &input,
            CellContextV1 {
                family: "persistent-v2-test".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            },
            16_384,
        )
        .unwrap();
    (dir, path, manifest, bytes)
}

fn client_limits() -> CellPersistentPeerLimitsV2 {
    CellPersistentPeerLimitsV2 {
        peer: CellPeerLimitsV1 {
            request_timeout: Duration::from_secs(1),
            overall_timeout: Duration::from_secs(5),
            max_cell_bytes: 1_048_576,
            parallelism: 2,
            max_connections: 1,
            max_response_bytes: 1_048_576,
        },
        max_requests: 3,
        max_requests_per_connection: 3,
    }
}

fn server_limits() -> CellPersistentServeLimitsV2 {
    CellPersistentServeLimitsV2 {
        serving: CellServeLimitsV1 {
            request_timeout: Duration::from_secs(1),
            overall_timeout: Duration::from_secs(5),
            max_workers: 2,
            max_connections: 4,
            max_response_bytes: 1_048_576,
        },
        max_requests: 16,
        max_requests_per_connection: 4,
    }
}

struct Server {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<CellResultV1<CellPersistentServeReportV2>>>,
}

impl Server {
    fn start(path: &Path, limits: CellPersistentServeLimitsV2) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        let path = path.to_owned();
        let worker = thread::spawn(move || serve_cells_persistent(&listener, &path, &stop, limits));
        Self {
            address,
            shutdown,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> CellPersistentServeReportV2 {
        self.shutdown.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn query(kind: u8, digest: CellDigestV1) -> [u8; 37] {
    let mut query = [0; 37];
    query[..4].copy_from_slice(b"TCQ2");
    query[4] = kind;
    query[5..].copy_from_slice(&digest);
    query
}

fn response(magic: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut response = magic.to_vec();
    response.push(0);
    response.extend_from_slice(&(body.len() as u32).to_be_bytes());
    response.extend_from_slice(body);
    response
}

fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                return stream;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            result => panic!("expected actual bounded TCP connection: {result:?}"),
        }
    }
}

fn read_body(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0; 9];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(&header[..5], b"TCS2\0");
    let length = u32::from_be_bytes(header[5..].try_into().unwrap()) as usize;
    assert!((1..=16_384).contains(&length));
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    body
}

#[test]
fn real_manifest_and_two_chunks_reuse_one_connection_and_original_response_budget() {
    for cached_manifest in [false, true] {
        let (dir, path, manifest, bytes) = fixture();
        let cache = CellStoreV1::open(&dir.path().join("receiver.sqlite"), cache_config()).unwrap();
        if cached_manifest {
            cache
                .put_manifest(manifest.id(), &manifest.encode())
                .unwrap();
        }
        let requests = if cached_manifest { 2 } else { 3 };
        let wire_bytes = bytes.len() as u64
            + requests * 9
            + if cached_manifest {
                0
            } else {
                manifest.encode().len() as u64
            };
        let mut serving = server_limits();
        serving.serving.max_connections = 1;
        serving.serving.max_response_bytes = wire_bytes;
        serving.max_requests = requests;
        serving.max_requests_per_connection = requests;
        let server = Server::start(&path, serving);
        let mut limits = client_limits();
        limits.peer.max_response_bytes = wire_bytes;
        limits.max_requests = requests;
        limits.max_requests_per_connection = requests;
        let output = dir.path().join("complete.weights");
        let result = fetch_cell_persistent_to_file(
            &cache,
            manifest.id(),
            &[server.address],
            limits,
            &output,
        );
        let served = server.finish();
        let (actual, report) = result.unwrap();
        assert_eq!(actual, manifest);
        assert_eq!(fs::read(output).unwrap(), bytes);
        assert_eq!(report.request_attempts, requests);
        assert_eq!(report.fetch.connection_attempts, 1);
        assert_eq!(report.fetch.received_response_bytes, wire_bytes);
        assert_eq!(report.fetch.downloaded_chunks, 2);
        assert_eq!(served.request_attempts, requests);
        assert_eq!(served.serving.accepted_connections, 1);
        assert_eq!(served.serving.completed_requests, requests);
        assert_eq!(served.serving.sent_response_bytes, wire_bytes);
    }
}

#[test]
fn request_connection_and_byte_exhaustion_each_refuse_output_and_keep_verified_prefix() {
    for budget in ["requests", "connections", "bytes"] {
        let (dir, path, manifest, bytes) = fixture();
        let cache = CellStoreV1::open(&dir.path().join("receiver.sqlite"), cache_config()).unwrap();
        cache
            .put_manifest(manifest.id(), &manifest.encode())
            .unwrap();
        let mut serving = server_limits();
        serving.max_requests_per_connection = if budget == "bytes" { 2 } else { 1 };
        let server = Server::start(&path, serving);
        let mut limits = client_limits();
        limits.peer.parallelism = 1;
        limits.max_requests = 2;
        limits.max_requests_per_connection = if budget == "bytes" { 2 } else { 1 };
        if budget == "requests" {
            limits.max_requests = 1;
            limits.peer.max_connections = 2;
        } else if budget == "bytes" {
            limits.peer.max_response_bytes = 2 * (9 + 16_384) - 1;
        }
        let output = dir.path().join("must-not-exist");
        let result = fetch_cell_persistent_to_file(
            &cache,
            manifest.id(),
            &[server.address],
            limits,
            &output,
        );
        assert!(result.is_err(), "{budget}");
        assert!(!output.exists(), "{budget}");
        assert_eq!(
            cache.chunk(manifest.chunks()[0].sha256).unwrap(),
            Some(bytes[..16_384].to_vec())
        );
        assert!(cache.chunk(manifest.chunks()[1].sha256).unwrap().is_none());
        let served = server.finish();
        assert_eq!(served.serving.accepted_connections, 1, "{budget}");
        // A later explicit invocation has a new reservation and requests only
        // the missing content object; the failed call cannot renew itself.
        let retry = Server::start(&path, server_limits());
        let mut retry_limits = client_limits();
        retry_limits.max_requests = 1;
        retry_limits.max_requests_per_connection = 1;
        retry_limits.peer.max_response_bytes = 9 + 16_384;
        let verified = dir.path().join("retry.weights");
        let result = fetch_cell_persistent_to_file(
            &cache,
            manifest.id(),
            &[retry.address],
            retry_limits,
            &verified,
        );
        retry.finish();
        let (_, report) = result.unwrap();
        assert_eq!(report.request_attempts, 1);
        assert_eq!(report.fetch.cached_chunks, 1);
        assert_eq!(report.fetch.downloaded_chunks, 1);
        assert_eq!(report.fetch.connection_attempts, 1);
        assert_eq!(fs::read(verified).unwrap(), bytes);
    }
}

#[test]
fn interrupted_frame_discards_connection_and_only_explicit_retry_spends_new_allowances() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut first = accept(&listener);
        let mut wire = [0; 37];
        first.read_exact(&mut wire).unwrap();
        assert_eq!(wire, query(2, [7; 32]));
        first.write_all(b"TC").unwrap();
        drop(first);
        let mut second = accept(&listener);
        second.read_exact(&mut wire).unwrap();
        assert_eq!(wire, query(2, [7; 32]));
        second.write_all(&response(b"TCS2", b"x")).unwrap();
    });
    let mut limits = client_limits();
    limits.peer.max_connections = 2;
    limits.max_requests = 2;
    limits.max_requests_per_connection = 2;
    let pool = ConnectionPool::new(&[peer], limits);
    let connections_left = AtomicU64::new(2);
    let responses = ResponseBudget::new(12);
    let transport = RequestContext {
        timeout: limits.peer.request_timeout,
        overall: Instant::now() + Duration::from_secs(5),
        requests_left: &connections_left,
        responses: &responses,
    };
    let (first, attempts) = pool.request(peer, 2, [7; 32], 1, &transport);
    assert!(first.is_err());
    assert_eq!(attempts, 1);
    assert_eq!(connections_left.load(Ordering::Relaxed), 1);
    assert_eq!(pool.requests_left.load(Ordering::Relaxed), 1);
    assert!(pool.peers[0].1.lock().unwrap().is_none());
    assert_eq!(responses.received().unwrap(), 2);
    let (second, attempts) = pool.request(peer, 2, [7; 32], 1, &transport);
    server.join().unwrap();
    assert_eq!(second.unwrap(), b"x");
    assert_eq!(attempts, 1);
    assert_eq!(connections_left.load(Ordering::Relaxed), 0);
    assert_eq!(pool.requests_left.load(Ordering::Relaxed), 0);
    assert_eq!(responses.received().unwrap(), 12);
}

#[test]
fn old_response_magic_is_rejected_without_namespace_fallback_or_redial() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut stream = accept(&listener);
        let mut wire = [0; 37];
        stream.read_exact(&mut wire).unwrap();
        assert_eq!(wire, query(2, [7; 32]));
        stream.write_all(&response(b"TCS1", b"x")).unwrap();
    });
    let limits = client_limits();
    let pool = ConnectionPool::new(&[peer], limits);
    let connections_left = AtomicU64::new(1);
    let responses = ResponseBudget::new(64);
    let transport = RequestContext {
        timeout: limits.peer.request_timeout,
        overall: Instant::now() + Duration::from_secs(5),
        requests_left: &connections_left,
        responses: &responses,
    };
    let (result, attempts) = pool.request(peer, 2, [7; 32], 1, &transport);
    server.join().unwrap();
    assert!(result.is_err());
    assert_eq!(attempts, 1);
    assert!(responses.is_quarantined(peer).unwrap());
    assert!(pool.peers[0].1.lock().unwrap().is_none());
    assert!(pool.request(peer, 2, [7; 32], 1, &transport).0.is_err());
    assert_eq!(connections_left.load(Ordering::Relaxed), 0);
    assert_eq!(
        pool.requests_left.load(Ordering::Relaxed),
        limits.max_requests - 1
    );
    assert_eq!(responses.received().unwrap(), 9);
}

#[test]
fn reuse_keeps_original_connection_deadline_and_expired_session_cannot_redial() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut stream = accept(&listener);
        for _ in 0..2 {
            let mut wire = [0; 37];
            stream.read_exact(&mut wire).unwrap();
            assert_eq!(wire, query(2, [7; 32]));
            stream.write_all(&response(b"TCS2", b"x")).unwrap();
        }
    });
    let limits = client_limits();
    let pool = ConnectionPool::new(&[peer], limits);
    let connections_left = AtomicU64::new(1);
    let responses = ResponseBudget::new(64);
    let overall = Instant::now() + Duration::from_secs(5);
    let transport = RequestContext {
        timeout: Duration::from_secs(1),
        overall,
        requests_left: &connections_left,
        responses: &responses,
    };
    assert_eq!(
        pool.request(peer, 2, [7; 32], 1, &transport).0.unwrap(),
        b"x"
    );
    let original = pool.peers[0].1.lock().unwrap().as_ref().unwrap().deadline;
    assert_eq!(
        pool.request(peer, 2, [7; 32], 1, &transport).0.unwrap(),
        b"x"
    );
    server.join().unwrap();
    assert_eq!(
        pool.peers[0].1.lock().unwrap().as_ref().unwrap().deadline,
        original
    );
    assert!(original < overall);
    let expired = RequestContext {
        overall: Instant::now() - Duration::from_millis(1),
        ..transport
    };
    assert!(pool.request(peer, 2, [7; 32], 1, &expired).0.is_err());
    assert_eq!(
        pool.requests_left.load(Ordering::Relaxed),
        limits.max_requests - 2
    );
    assert_eq!(connections_left.load(Ordering::Relaxed), 0);
    assert_eq!(responses.received().unwrap(), 20);
}

#[test]
fn server_rejects_old_magic_and_unknown_kind_without_serving_object_bytes() {
    let (_dir, path, manifest, _) = fixture();
    for (magic, kind) in [(b"TCQ1", 2), (b"TCI1", 1), (b"TCQ2", 3)] {
        let mut limits = server_limits();
        limits.serving.max_connections = 1;
        limits.max_requests = 1;
        limits.max_requests_per_connection = 1;
        let server = Server::start(&path, limits);
        let mut stream = TcpStream::connect(server.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut wire = query(kind, manifest.chunks()[0].sha256);
        wire[..4].copy_from_slice(magic);
        stream.write_all(&wire).unwrap();
        let mut byte = [0; 1];
        assert_eq!(stream.read(&mut byte).unwrap(), 0);
        let report = server.finish();
        assert_eq!(report.request_attempts, 1);
        assert_eq!(report.serving.accepted_connections, 1);
        assert_eq!(report.serving.completed_requests, 0);
        assert_eq!(report.serving.sent_response_bytes, 0);
    }
}

#[test]
fn server_frame_and_byte_budgets_apply_across_reused_requests() {
    let (_dir, path, manifest, bytes) = fixture();
    for cap in ["requests", "per-connection", "bytes"] {
        let mut limits = server_limits();
        limits.serving.max_connections = 1;
        if cap == "requests" {
            limits.max_requests = 1;
        }
        limits.max_requests_per_connection = if cap == "bytes" { 2 } else { 1 };
        if cap == "bytes" {
            limits.serving.max_response_bytes = (9 + 16_384) as u64 + 10;
        }
        let server = Server::start(&path, limits);
        let mut stream = TcpStream::connect(server.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(&query(2, manifest.chunks()[0].sha256))
            .unwrap();
        assert_eq!(read_body(&mut stream), bytes[..16_384]);
        let _ = stream.write_all(&query(2, manifest.chunks()[1].sha256));
        let mut remainder = Vec::new();
        match stream.read_to_end(&mut remainder) {
            Ok(_) => (),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) => {}
            Err(error) => panic!("{cap}: {error}"),
        }
        let report = server.finish();
        assert_eq!(report.serving.accepted_connections, 1);
        assert_eq!(report.serving.completed_requests, 1);
        assert_eq!(report.request_attempts, if cap == "bytes" { 2 } else { 1 });
        assert_eq!(remainder.len(), if cap == "bytes" { 10 } else { 0 });
        assert_eq!(
            report.serving.sent_response_bytes,
            9 + 16_384 + remainder.len() as u64
        );
    }
}

#[test]
fn server_actual_egress_exhaustion_stops_intake_and_next_frame_without_shutdown() {
    let (_dir, path, manifest, bytes) = fixture();
    let wire = response(b"TCS2", &bytes[..16_384]);
    for maximum in [0, 10, wire.len() as u64] {
        let mut limits = server_limits();
        limits.serving.max_response_bytes = maximum;
        // Connection/request/timeout bounds deliberately have room left. The
        // actual byte quota must stop this owner without a shutdown request.
        let server = Server::start(&path, limits);
        let mut received = Vec::new();
        match TcpStream::connect_timeout(&server.address, Duration::from_secs(2)) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let _ = stream.write_all(&query(2, manifest.chunks()[0].sha256));
                match stream.read_to_end(&mut received) {
                    Ok(_) => (),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                        ) => {}
                    Err(error) => panic!("byte quota {maximum}: {error}"),
                }
            }
            Err(error) if maximum == 0 && error.kind() == io::ErrorKind::ConnectionRefused => (),
            Err(error) => panic!("byte quota {maximum}: {error}"),
        }
        let cutoff = Instant::now() + Duration::from_secs(2);
        while !server.worker.as_ref().unwrap().is_finished() && Instant::now() < cutoff {
            thread::sleep(Duration::from_millis(1));
        }
        let stopped_without_shutdown = server.worker.as_ref().unwrap().is_finished();
        let report = server.finish();
        assert!(stopped_without_shutdown, "byte quota {maximum}");
        assert_eq!(received, wire[..maximum as usize]);
        assert_eq!(report.serving.sent_response_bytes, maximum);
        assert_eq!(report.serving.accepted_connections, u64::from(maximum != 0));
        assert_eq!(report.request_attempts, u64::from(maximum != 0));
        assert_eq!(
            report.serving.completed_requests,
            u64::from(maximum == wire.len() as u64)
        );
    }
}

#[test]
fn server_temporary_egress_reservation_refunds_before_real_tcp_response() {
    let (_dir, path, manifest, bytes) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let maximum = 9 + 16_384;
    let responses = ResponseBudget::new(maximum);
    let requests_left = AtomicU64::new(1);
    let shutdown = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(3);
    let reserved = responses.reserve(maximum as usize, deadline).unwrap();
    assert_eq!(responses.received().unwrap(), 0);
    thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let mut stream = accept(&listener);
            let store = CellStoreV1::open_read_only(&path).unwrap();
            serve_connection(
                &mut stream,
                &store,
                &shutdown,
                deadline,
                1,
                &requests_left,
                &responses,
            )
        });
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .write_all(&query(2, manifest.chunks()[0].sha256))
            .unwrap();
        let cutoff = Instant::now() + Duration::from_secs(2);
        while requests_left.load(Ordering::Relaxed) != 0
            && !worker.is_finished()
            && Instant::now() < cutoff
        {
            thread::sleep(Duration::from_millis(1));
        }
        let admitted_while_reserved = requests_left.load(Ordering::Relaxed) == 0;
        // Return the outstanding allowance before asserting, so a failed test
        // still joins its real worker under the same fixed deadline.
        responses.complete(reserved, 0).unwrap();
        assert!(admitted_while_reserved);
        assert_eq!(read_body(&mut stream), bytes[..16_384]);
        assert_eq!(worker.join().unwrap(), 1);
    });
    assert_eq!(responses.received().unwrap(), maximum);
    assert_eq!(requests_left.load(Ordering::Relaxed), 0);
}

#[test]
fn invalid_persistent_limits_never_open_transport_or_mutate_the_cache() {
    let (dir, _, manifest, _) = fixture();
    let cache = CellStoreV1::open(&dir.path().join("receiver.sqlite"), cache_config()).unwrap();
    for (total, per_connection) in [(0, 0), (1, 0), (1, 2), (MAX_REQUESTS + 1, 1)] {
        let limits = CellPersistentPeerLimitsV2 {
            max_requests: total,
            max_requests_per_connection: per_connection,
            ..client_limits()
        };
        assert!(matches!(
            fetch_cell_persistent(&cache, manifest.id(), &[], limits),
            Err(CellErrorV1::Invalid("persistent request bounds"))
        ));
        let serving = CellPersistentServeLimitsV2 {
            max_requests: total,
            max_requests_per_connection: per_connection,
            ..server_limits()
        };
        assert!(serving.validate().is_err());
        assert!(cache.manifest(manifest.id()).unwrap().is_none());
    }
}
