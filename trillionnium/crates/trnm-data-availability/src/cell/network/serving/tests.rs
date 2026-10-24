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
fn cache_config() -> crate::cell::CellCacheConfigV3 {
    crate::cell::CellCacheConfigV3 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: 64 * 1024 * 1024,
        max_chunk_rows: 4096,
        max_manifest_rows: 256,
    }
}
