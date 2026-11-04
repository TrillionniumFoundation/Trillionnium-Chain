use super::*;
use crate::cell::{fetch_cell, CellContextV1};
use std::{fs, sync::Arc, thread::JoinHandle};

fn limits() -> CellServeLimitsV1 {
    CellServeLimitsV1 {
        request_timeout: Duration::from_secs(1),
        overall_timeout: Duration::from_secs(5),
        max_workers: 2,
        max_connections: 100,
        max_response_bytes: 1_048_576,
    }
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, CellManifestV1) {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("weights");
    fs::write(&input, [7_u8; 16_384]).unwrap();
    let path = dir.path().join("cache.sqlite");
    let store = CellStoreV1::open(&path, cache_config()).unwrap();
    let manifest = store
        .pack_file(
            &input,
            CellContextV1 {
                family: "serving-test".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            },
            16_384,
        )
        .unwrap();
    (dir, path, manifest)
}

struct Server {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    seen: mpsc::Receiver<CellServeReportV1>,
    handle: JoinHandle<CellResultV1<CellServeReportV1>>,
}
impl Server {
    fn start(path: &Path, limits: CellServeLimitsV1) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let path = path.to_owned();
        let (sender, seen) = mpsc::channel();
        let handle = thread::spawn(move || {
            serve_cells_inner(&listener, &path, &shutdown, limits, &|report| {
                let _ = sender.send(report.clone());
            })
        });
        Self {
            address,
            stop,
            seen,
            handle,
        }
    }
    fn accepted(&self, n: u64) -> CellServeReportV1 {
        loop {
            let report = self.seen.recv_timeout(Duration::from_secs(2)).unwrap();
            if report.accepted_connections == n {
                return report;
            }
        }
    }
    fn finish(self) -> CellServeReportV1 {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().unwrap().unwrap()
    }
}
fn query(manifest: &CellManifestV1) -> Vec<u8> {
    let mut query = b"TCQ1\x01".to_vec();
    query.extend(manifest.id());
    query
}

#[cfg(unix)]
#[test]
fn listener_wait_is_capped_by_the_original_deadline_and_idle_interval() {
    let now = Instant::now();
    assert_eq!(listener_wait_timeout(now, now), Duration::ZERO);
    assert_eq!(
        listener_wait_timeout(now, now + Duration::from_nanos(1)),
        Duration::ZERO
    );
    assert_eq!(
        listener_wait_timeout(now + Duration::from_micros(123), now),
        Duration::from_micros(123)
    );
    assert_eq!(
        listener_wait_timeout(now + Duration::from_secs(30), now),
        Duration::from_millis(5)
    );
}

#[cfg(unix)]
#[test]
fn quiet_listener_wait_times_out_without_accepting_or_extending_the_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_millis(2);
    assert!(!wait_for_listener(&listener, deadline).unwrap());
    assert!(Instant::now() >= deadline);
    // Reusing the expired deadline must not start another wait or invent
    // readiness. No exact wall-clock upper bound assumes scheduler isolation.
    assert!(!wait_for_listener(&listener, deadline).unwrap());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[cfg(unix)]
#[test]
fn ready_listener_wait_leaves_the_socket_for_the_original_accept_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client.write_all(b"cell-readiness").unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    assert!(wait_for_listener(&listener, deadline).unwrap());
    let (mut accepted, _) = listener.accept().unwrap();
    accepted
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut bytes = [0; 14];
    accepted.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"cell-readiness");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    // Even a queued connection does not renew an already expired service.
    let _next = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    assert!(!wait_for_listener(&listener, Instant::now()).unwrap());
}

#[test]
fn half_request_does_not_block_honest_pinned_fetch() {
    let (dir, path, manifest) = fixture();
    let server = Server::start(
        &path,
        CellServeLimitsV1 {
            max_workers: 3,
            ..limits()
        },
    );
    let mut slow = TcpStream::connect(server.address).unwrap();
    slow.write_all(b"T").unwrap();
    server.accepted(1);
    let cache = CellStoreV1::open(&dir.path().join("consumer.sqlite"), cache_config()).unwrap();
    let (actual, report) = fetch_cell(
        &cache,
        manifest.id(),
        &[server.address],
        CellPeerLimitsV1 {
            request_timeout: Duration::from_millis(300),
            overall_timeout: Duration::from_millis(900),
            max_cell_bytes: 16_384,
            parallelism: 1,
            max_connections: 2,
            max_response_bytes: 20_000,
        },
    )
    .unwrap();
    assert_eq!(actual, manifest);
    assert_eq!(report.downloaded_bytes, 16_384);
    slow.set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    assert!(matches!(
        slow.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    drop(slow);
    let report = server.finish();
    assert_eq!(report.completed_requests, 2);
    assert!(report.peak_active_workers >= 2 && report.peak_active_workers <= 3);
}

#[test]
fn active_limit_drops_overload_without_queue_or_extra_bytes() {
    let (_dir, path, _) = fixture();
    let server = Server::start(
        &path,
        CellServeLimitsV1 {
            max_connections: 3,
            ..limits()
        },
    );
    let a = TcpStream::connect(server.address).unwrap();
    server.accepted(1);
    let b = TcpStream::connect(server.address).unwrap();
    server.accepted(2);
    let mut excess = TcpStream::connect(server.address).unwrap();
    let observed = server.accepted(3);
    assert_eq!(observed.overloaded_connections, 1);
    excess
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(matches!(excess.read(&mut [0; 1]), Ok(0)));
    drop((a, b));
    let report = server.finish();
    assert_eq!(report.accepted_connections, 3);
    assert_eq!(report.peak_active_workers, 2);
    assert_eq!(report.completed_requests, 0);
    assert_eq!(report.sent_response_bytes, 0);
}

fn transient_capacity_refusal(cached_manifest: bool) {
    let (dir, path, manifest) = fixture();
    let server = Server::start(&path, limits());
    let a = TcpStream::connect(server.address).unwrap();
    server.accepted(1);
    let b = TcpStream::connect(server.address).unwrap();
    server.accepted(2);
    let client_path = dir.path().join("retry-consumer.sqlite");
    let expected = manifest.clone();
    let address = server.address;
    let maximum = if cached_manifest { 2 } else { 3 };
    let client = thread::spawn(move || {
        let cache = CellStoreV1::open(&client_path, cache_config()).unwrap();
        if cached_manifest {
            cache
                .put_manifest(expected.id(), &expected.encode())
                .unwrap();
        }
        fetch_cell(
            &cache,
            expected.id(),
            &[address],
            CellPeerLimitsV1 {
                request_timeout: Duration::from_millis(300),
                overall_timeout: Duration::from_secs(1),
                max_cell_bytes: 16_384,
                parallelism: 1,
                max_connections: maximum,
                max_response_bytes: 20_000,
            },
        )
    });
    // Both actual workers are occupied. This first honest request is really
    // refused by the existing bounded server; no success result is substituted.
    let overload = server.accepted(3);
    assert_eq!(overload.overloaded_connections, 1);
    drop((a, b));
    let result = client.join().unwrap();
    let served = server.finish();
    let (actual, fetched) = result.expect("one transient refusal must allow one bounded retry");
    assert_eq!(actual, manifest);
    assert_eq!(fetched.downloaded_bytes, 16_384);
    assert_eq!(fetched.connection_attempts, maximum);
    assert_eq!(fetched.rejected_responses, 1);
    assert_eq!(served.peak_active_workers, 2);
    assert_eq!(served.overloaded_connections, 1);
    assert_eq!(served.accepted_connections, maximum + 2);
}

#[test]
fn transient_manifest_capacity_refusal_uses_one_bounded_retry() {
    transient_capacity_refusal(false);
}

#[test]
fn transient_chunk_capacity_refusal_uses_one_bounded_retry() {
    transient_capacity_refusal(true);
}

#[test]
fn concurrent_responses_share_exact_byte_budget_and_one_byte_short_cutoff() {
    for short in [0, 1] {
        let (_dir, path, manifest) = fixture();
        let length = manifest.encode().len() + 9;
        let maximum = (2 * length - short) as u64;
        let server = Server::start(
            &path,
            CellServeLimitsV1 {
                max_connections: 2,
                max_response_bytes: maximum,
                ..limits()
            },
        );
        let mut sockets = Vec::new();
        let request = query(&manifest);
        for count in 1..=2 {
            let mut socket = TcpStream::connect(server.address).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket.write_all(&request[..4]).unwrap();
            server.accepted(count);
            sockets.push(socket);
        }
        for socket in &mut sockets {
            socket.write_all(&request[4..]).unwrap();
        }
        let mut received = 0;
        let mut complete = 0;
        for mut socket in sockets {
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).unwrap();
            received += bytes.len();
            if bytes.len() == length {
                assert_eq!(&bytes[9..], manifest.encode());
                complete += 1;
            }
        }
        let report = server.finish();
        assert_eq!(received as u64, maximum);
        assert_eq!(report.sent_response_bytes, maximum);
        assert_eq!(report.completed_requests, complete);
        assert_eq!(complete, if short == 0 { 2 } else { 1 });
        assert_eq!(report.peak_active_workers, 2);
    }
}

#[test]
fn original_overall_deadline_and_shutdown_join_all_admitted_workers() {
    for shutdown in [false, true] {
        let (_dir, path, _) = fixture();
        let server = Server::start(
            &path,
            CellServeLimitsV1 {
                request_timeout: Duration::from_millis(100),
                overall_timeout: if shutdown {
                    Duration::from_secs(5)
                } else {
                    Duration::from_millis(100)
                },
                ..limits()
            },
        );
        let mut slow = TcpStream::connect(server.address).unwrap();
        server.accepted(1);
        let start = Instant::now();
        let report = if shutdown {
            server.finish()
        } else {
            server.handle.join().unwrap().unwrap()
        };
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(report.accepted_connections, 1);
        assert_eq!(report.sent_response_bytes, 0);
        slow.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        assert_eq!(slow.read(&mut [0; 1]).unwrap(), 0);
    }
}

#[test]
fn invalid_limits_and_missing_or_foreign_cache_fail_without_creating_store() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let path = dir.path().join("absent.sqlite");
    for workers in [0, 5] {
        assert!(serve_cells_bounded(
            &listener,
            &path,
            &AtomicBool::new(false),
            CellServeLimitsV1 {
                max_workers: workers,
                ..limits()
            }
        )
        .is_err());
    }
    assert!(serve_cells_bounded(&listener, &path, &AtomicBool::new(false), limits()).is_err());
    assert!(!path.exists());
    let foreign = rusqlite::Connection::open(&path).unwrap();
    foreign
        .execute_batch("CREATE TABLE private_data(value BLOB)")
        .unwrap();
    assert!(serve_cells_bounded(&listener, &path, &AtomicBool::new(false), limits()).is_err());
    assert_eq!(
        foreign
            .pragma_query_value::<i64, _>(None, "application_id", |r| r.get(0))
            .unwrap(),
        0
    );
}

#[test]
fn double_worker_panic_is_joined_without_overwriting_the_first_error() {
    let (_dir, path, _) = fixture();
    for earlier_failure in [None, Some(CellErrorV1::Invalid("earlier serving failure"))] {
        let expected_message = if earlier_failure.is_some() {
            "earlier serving failure"
        } else {
            "cell serving worker panicked"
        };
        let readers = (0..2)
            .map(|_| CellStoreV1::open_read_only(&path).unwrap())
            .collect::<Vec<_>>();
        let barrier = std::sync::Barrier::new(2);
        let mut report = CellServeReportV1::default();
        let failure = thread::scope(|scope| {
            let mut active = readers
                .into_iter()
                .map(|store| {
                    let barrier = &barrier;
                    scope.spawn(move || -> (CellStoreV1, bool) {
                        let _owned_reader = store;
                        barrier.wait();
                        panic!("injected cell serving worker panic");
                    })
                })
                .collect::<Vec<_>>();
            let mut failure = earlier_failure;
            assert!(join_worker(active.remove(0), &mut report, &mut failure).is_none());
            let first_error = failure.as_ref().unwrap().to_string();
            for worker in active {
                assert!(join_worker(worker, &mut report, &mut failure).is_none());
            }
            assert_eq!(failure.as_ref().unwrap().to_string(), first_error);
            failure
        });
        assert!(
            matches!(failure, Some(CellErrorV1::Invalid(message)) if message == expected_message)
        );
        assert_eq!(report.completed_requests, 0);
    }
}

#[test]
fn four_workers_drop_fifth_socket_and_all_accepts_consume_the_cap() {
    let (_dir, path, _) = fixture();
    let server = Server::start(
        &path,
        CellServeLimitsV1 {
            max_workers: 4,
            max_connections: 5,
            ..limits()
        },
    );
    let mut active = Vec::new();
    for count in 1..=4 {
        active.push(TcpStream::connect(server.address).unwrap());
        assert_eq!(server.accepted(count).peak_active_workers, count as usize);
    }
    let mut excess = TcpStream::connect(server.address).unwrap();
    let report = server.accepted(5);
    assert_eq!(report.overloaded_connections, 1);
    excess
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert_eq!(excess.read(&mut [0; 1]).unwrap(), 0);
    drop(active);
    let report = server.finish();
    assert_eq!(report.accepted_connections, 5);
    assert_eq!(report.peak_active_workers, 4);
    assert_eq!(report.completed_requests, 0);
    assert_eq!(report.sent_response_bytes, 0);
}

#[cfg(unix)]
#[test]
fn unread_large_response_keeps_absolute_deadline_and_exact_partial_write_charge() {
    let (dir, path, manifest) = fixture();
    let input = dir.path().join("large");
    fs::write(&input, vec![7_u8; MAX_CHUNK_BYTES as usize]).unwrap();
    let source = CellStoreV1::open(&path, cache_config()).unwrap();
    let manifest = source
        .pack_file(&input, manifest.context().clone(), MAX_CHUNK_BYTES)
        .unwrap();
    drop(source);
    let started = Instant::now();
    let server = Server::start(
        &path,
        CellServeLimitsV1 {
            request_timeout: Duration::from_secs(1),
            overall_timeout: Duration::from_secs(1),
            max_workers: 4,
            max_connections: 1,
            max_response_bytes: 2 * u64::from(MAX_CHUNK_BYTES),
        },
    );
    let mut slow = TcpStream::connect(server.address).unwrap();
    rustix::net::sockopt::set_socket_recv_buffer_size(&slow, 4096).unwrap();
    let mut request = b"TCQ1\x02".to_vec();
    request.extend(manifest.chunks()[0].sha256);
    slow.write_all(&request).unwrap();
    server.accepted(1);
    // No response read until the real service has joined its blocked writer.
    let report = server.handle.join().unwrap().unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(report.accepted_connections, 1);
    assert_eq!(report.completed_requests, 0);
    assert!(report.sent_response_bytes > 9);
    assert!(report.sent_response_bytes < u64::from(MAX_CHUNK_BYTES) + 9);
    // Dropping unread bytes must not make them disappear from actual charges.
    drop(slow);
}

#[cfg(unix)]
#[test]
fn bounded_reader_rejects_real_discovery_and_retention_namespaces_unchanged() {
    use crate::cell::{
        discovery::{CellDiscoveryContextV1, CellProviderDirectoryV1},
        CellRetentionConfigV1, CellRetentionStoreV1,
    };
    let dir = tempfile::tempdir().unwrap();
    let directory_path = dir.path().join("directory.sqlite");
    let _directory = CellProviderDirectoryV1::open(
        &directory_path,
        CellDiscoveryContextV1 {
            namespace: [1; 32],
            network: [2; 32],
            parameters: [3; 32],
            genesis: [4; 32],
        },
    )
    .unwrap();
    let retention_path = dir.path().join("retention");
    let _retention = CellRetentionStoreV1::create(
        &retention_path,
        CellRetentionConfigV1 {
            store_id: [5; 32],
            capacity_bytes: 4096,
            maximum_obligations: 1,
        },
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    for (path, table) in [
        (directory_path, "discovery_meta_v1"),
        (retention_path.join("retention.sqlite"), "metadata"),
    ] {
        let db = rusqlite::Connection::open(&path).unwrap();
        let app: i64 = db
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .unwrap();
        let rows: u64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        let original = fs::read(&path).unwrap();
        let error =
            serve_cells_bounded(&listener, &path, &AtomicBool::new(false), limits()).unwrap_err();
        assert!(matches!(error, CellErrorV1::Invalid("cache namespace")));
        assert_eq!(
            db.pragma_query_value::<i64, _>(None, "application_id", |row| row.get(0))
                .unwrap(),
            app
        );
        assert_eq!(
            db.query_row::<u64, _, _>(&format!("SELECT count(*) FROM {table}"), [], |row| row
                .get(0))
                .unwrap(),
            rows
        );
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[test]
fn bounded_corrupt_chunk_read_keeps_row_then_writable_fetch_repairs_exact_pin() {
    let (dir, path, manifest) = fixture();
    let chunk = &manifest.chunks()[0];
    let bad = vec![8_u8; chunk.size as usize];
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE cell_chunks_v1 SET bytes=? WHERE hash=?",
        rusqlite::params![&bad, chunk.sha256.as_slice()],
    )
    .unwrap();
    let server = Server::start(
        &path,
        CellServeLimitsV1 {
            max_connections: 1,
            ..limits()
        },
    );
    let mut socket = TcpStream::connect(server.address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut query = b"TCQ1\x02".to_vec();
    query.extend(chunk.sha256);
    socket.write_all(&query).unwrap();
    let mut reply = Vec::new();
    socket.read_to_end(&mut reply).unwrap();
    let report = server.finish();
    assert_eq!(reply, b"TCS1\x01\0\0\0\0");
    assert_eq!(report.sent_response_bytes, 9);
    let readback: Vec<u8> = db
        .query_row(
            "SELECT bytes FROM cell_chunks_v1 WHERE hash=?",
            [chunk.sha256.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(readback, bad); // Read-only serving cannot repair/delete corruption.
    let healthy_path = dir.path().join("healthy.sqlite");
    let healthy = CellStoreV1::open(&healthy_path, cache_config()).unwrap();
    assert_eq!(
        healthy
            .pack_file(
                &dir.path().join("weights"),
                manifest.context().clone(),
                chunk.size
            )
            .unwrap()
            .id(),
        manifest.id()
    );
    let server = Server::start(
        &healthy_path,
        CellServeLimitsV1 {
            max_connections: 1,
            ..limits()
        },
    );
    let receiver = CellStoreV1::open(&path, cache_config()).unwrap();
    let (received, report) = fetch_cell(
        &receiver,
        manifest.id(),
        &[server.address],
        CellPeerLimitsV1 {
            request_timeout: Duration::from_secs(1),
            overall_timeout: Duration::from_secs(2),
            max_cell_bytes: 16384,
            parallelism: 1,
            max_connections: 1,
            max_response_bytes: 16384 + 9,
        },
    )
    .unwrap();
    assert_eq!(received, manifest);
    assert_eq!(report.downloaded_chunks, 1);
    assert_eq!(
        receiver.chunk(chunk.sha256).unwrap().unwrap(),
        vec![7_u8; chunk.size as usize]
    );
    assert_eq!(server.finish().completed_requests, 1);
}

// Explicit finite fixture quota; covers the existing <=32MiB commit fixtures.
fn cache_config() -> crate::cell::CellCacheConfigV4 {
    crate::cell::CellCacheConfigV4 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: 64 * 1024 * 1024,
        max_chunk_rows: 4096,
        max_manifest_rows: 256,
    }
}

#[test]
fn exhausted_serving_budget_refuses_before_fresh_payload_lookup() {
    let (_dir, path, manifest) = fixture();
    let store = CellStoreV1::open_read_only(&path).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let budget = ResponseBudget::new(9);
    let mut query = b"TCQ1\x02".to_vec();
    query.extend([0; 32]);
    let mut first = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    first.write_all(&query).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    // A real absent-chunk response spends the complete original egress grant.
    serve_one_budgeted(&mut stream, &store, deadline, Some(&budget)).unwrap();
    let mut response = [0_u8; 9];
    first.read_exact(&mut response).unwrap();
    assert_eq!(&response[..5], b"TCS1\x01");
    assert_eq!(budget.received().unwrap(), 9);
    drop((stream, first));

    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE cell_chunks_v1")
        .unwrap();
    query[5..].copy_from_slice(&manifest.chunks()[0].sha256);
    let mut second = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    second.write_all(&query).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    assert!(matches!(
        serve_one_budgeted(&mut stream, &store, deadline, Some(&budget)),
        Err(CellErrorV1::Io(error)) if error.to_string() == "CELL_RESPONSE_BYTE_BUDGET_EXHAUSTED"
    ));
    assert_eq!(budget.received().unwrap(), 9);
    drop(stream);
    let mut bytes = Vec::new();
    second.read_to_end(&mut bytes).unwrap();
    assert!(bytes.is_empty());
    // Storage was actually broken; the exhausted branch must not read it.
    assert!(matches!(
        store.chunk(manifest.chunks()[0].sha256),
        Err(CellErrorV1::Sql(_))
    ));
}

#[test]
fn zero_serving_byte_budget_admits_no_socket_or_payload_worker() {
    let (_dir, path, _manifest) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _queued = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let report = serve_cells_bounded(
        &listener,
        &path,
        &AtomicBool::new(false),
        CellServeLimitsV1 {
            max_response_bytes: 0,
            max_connections: 1,
            request_timeout: Duration::from_millis(10),
            overall_timeout: Duration::from_millis(10),
            ..limits()
        },
    )
    .unwrap();
    assert_eq!(report, CellServeReportV1::default());
}

#[test]
fn positive_exhaustion_stops_intake_and_joins_admitted_half_request() {
    let (_dir, path, _manifest) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (observed, seen) = mpsc::channel();
    let (resume, intake) = mpsc::channel();
    let intake = std::sync::Mutex::new(intake);
    let handle = thread::spawn(move || {
        serve_cells_inner(
            &listener,
            &path,
            &AtomicBool::new(false),
            CellServeLimitsV1 {
                max_connections: 20,
                max_response_bytes: 9,
                request_timeout: Duration::from_millis(750),
                overall_timeout: Duration::from_secs(3),
                ..limits()
            },
            &|report| {
                observed.send(report.clone()).unwrap();
                if report.accepted_connections == 2 {
                    // Stop only the intake observer. The real socket workers
                    // retain their original deadlines and run normally.
                    intake
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(2))
                        .unwrap();
                }
            },
        )
    });
    let mut half = TcpStream::connect(address).unwrap();
    half.write_all(b"T").unwrap();
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(2))
            .unwrap()
            .accepted_connections,
        1
    );
    let mut absent = TcpStream::connect(address).unwrap();
    let mut query = b"TCQ1\x02".to_vec();
    query.extend([0; 32]);
    absent.write_all(&query).unwrap();
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(2))
            .unwrap()
            .accepted_connections,
        2
    );
    absent
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut response = [0_u8; 9];
    absent.read_exact(&mut response).unwrap();
    assert_eq!(&response[..5], b"TCS1\x01");
    // EOF follows worker completion and actual-byte accounting, whereas
    // kernel delivery alone can precede the sender's accounting checkpoint.
    assert_eq!(absent.read(&mut [0; 1]).unwrap(), 0);
    // The original positive grant was actually written before another socket
    // is queued. No shutdown or max_connections exit can mask the intake guard.
    let _queued = TcpStream::connect(address).unwrap();
    resume.send(()).unwrap();
    let report = handle.join().unwrap().unwrap();
    assert_eq!(report.accepted_connections, 2);
    assert_eq!(report.completed_requests, 1);
    assert_eq!(report.peak_active_workers, 2);
    assert_eq!(report.overloaded_connections, 0);
    assert_eq!(report.sent_response_bytes, 9);
    half.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    assert_eq!(half.read(&mut [0; 1]).unwrap(), 0);
}
