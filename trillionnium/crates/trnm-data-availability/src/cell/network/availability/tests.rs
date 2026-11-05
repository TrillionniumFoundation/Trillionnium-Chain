use super::*;
use crate::cell::{CellCacheConfigV4, CellContextV1};
use std::{fs, path::PathBuf, sync::Arc, thread::JoinHandle};

fn cache_config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_logical_bytes: 8 * 1024 * 1024,
        max_manifest_rows: 64,
        max_chunk_rows: 1024,
        max_database_bytes: 16 * 1024 * 1024,
    }
}

fn limits() -> CellPeerLimitsV1 {
    CellPeerLimitsV1 {
        request_timeout: Duration::from_secs(2),
        overall_timeout: Duration::from_secs(15),
        max_cell_bytes: 8 * 1024 * 1024,
        parallelism: 1,
        max_connections: 64,
        max_response_bytes: 8 * 1024 * 1024,
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf, CellManifestV1, Vec<Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    let chunks: Vec<_> = (1..=3).map(|value| vec![value; 16_384]).collect();
    let input = dir.path().join("weights");
    fs::write(&input, chunks.concat()).unwrap();
    let cache = dir.path().join("source.sqlite");
    let store = CellStoreV1::open(&cache, cache_config()).unwrap();
    let manifest = store
        .pack_file(
            &input,
            CellContextV1 {
                family: "inventory-test".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            },
            16_384,
        )
        .unwrap();
    (dir, cache, manifest, chunks)
}

fn response(magic: &[u8; 4], bytes: Option<&[u8]>) -> Vec<u8> {
    let mut response = magic.to_vec();
    response.push(u8::from(bytes.is_none()));
    response.extend_from_slice(&(bytes.map_or(0, <[u8]>::len) as u32).to_be_bytes());
    if let Some(bytes) = bytes {
        response.extend_from_slice(bytes);
    }
    response
}

struct Peer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    handle: Option<JoinHandle<()>>,
}

impl Peer {
    fn start(handler: impl Fn(&[u8], usize) -> Option<Vec<u8>> + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            while !shutdown.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut query = vec![0; 37];
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        if stream.read_exact(&mut query).is_err() {
                            continue;
                        }
                        if &query[..4] == b"TCI1" {
                            query.resize(43, 0);
                            if stream.read_exact(&mut query[37..]).is_err() {
                                continue;
                            }
                        }
                        let call = observed.fetch_add(1, Ordering::Relaxed);
                        if let Some(bytes) = handler(&query, call) {
                            let _ = stream.write_all(&bytes);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("loopback accept failed: {error}"),
                }
            }
        });
        Self {
            address,
            stop,
            calls,
            handle: Some(handle),
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap();
    }
}

fn supplying_peer(
    manifest: CellManifestV1,
    chunks: Vec<Vec<u8>>,
    bits: u8,
    order: Arc<Mutex<Vec<usize>>>,
) -> Peer {
    Peer::start(move |query, _| {
        if &query[..4] == b"TCI1" {
            assert_eq!(&query[5..37], &manifest.id());
            assert_eq!(&query[37..], &[0, 0, 0, 0, 0, 3]);
            return Some(response(b"TIS1", Some(&[bits])));
        }
        if query[4] == 1 {
            return Some(response(b"TCS1", Some(&manifest.encode())));
        }
        let index = manifest
            .chunks()
            .iter()
            .position(|chunk| chunk.sha256.as_slice() == &query[5..])
            .unwrap();
        order.lock().unwrap().push(index);
        Some(response(
            b"TCS1",
            if bits & (1_u8 << index) == 0 {
                None
            } else {
                Some(&chunks[index])
            },
        ))
    })
}

#[test]
fn complete_bad_chunk_is_quarantined_for_later_chunks_in_original_session() {
    let (_dir, _path, manifest, chunks) = fixture();
    let bad = Peer::start(|_, _| Some(response(b"TCS1", Some(&[0; 16_384]))));
    let good = supplying_peer(manifest.clone(), chunks.clone(), 7, Arc::default());
    let requests_left = AtomicU64::new(10);
    let responses = ResponseBudget::new(200_000);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: Instant::now() + Duration::from_secs(10),
        requests_left: &requests_left,
        responses: &responses,
    };
    for (index, expected) in manifest.chunks()[..2].iter().enumerate() {
        let (bytes, peer, rejected) =
            download_chunk(expected, 0, &[bad.address, good.address], &transport).unwrap();
        assert_eq!(bytes, chunks[index]);
        assert_eq!(peer, good.address);
        assert_eq!(rejected, usize::from(index == 0));
    }
    assert!(responses.is_quarantined(bad.address).unwrap());
    assert_eq!(bad.calls.load(Ordering::Relaxed), 1);
    assert_eq!(good.calls.load(Ordering::Relaxed), 2);
    assert_eq!(requests_left.load(Ordering::Relaxed), 7);
    assert_eq!(responses.received().unwrap(), 3 * (9 + 16_384));
}

#[test]
fn wrong_manifest_quarantine_survives_into_the_same_session_payload_fetch() {
    let (dir, _path, manifest, chunks) = fixture();
    let mut wrong = manifest.encode();
    *wrong.last_mut().unwrap() ^= 1;
    let bad = Peer::start(move |_, _| Some(response(b"TCS1", Some(&wrong))));
    let good = supplying_peer(manifest.clone(), chunks.clone(), 7, Arc::default());
    let cache = CellStoreV1::open(&dir.path().join("consumer"), cache_config()).unwrap();
    let requests_left = AtomicU64::new(10);
    let responses = ResponseBudget::new(200_000);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: Instant::now() + Duration::from_secs(10),
        requests_left: &requests_left,
        responses: &responses,
    };
    let (observed, rejected) = fetch_manifest(
        &cache,
        manifest.id(),
        &[bad.address, good.address],
        limits(),
        &transport,
    )
    .unwrap();
    assert_eq!(observed, manifest);
    assert_eq!(rejected, 1);
    let (bytes, peer, _) = download_chunk(
        &manifest.chunks()[0],
        0,
        &[bad.address, good.address],
        &transport,
    )
    .unwrap();
    assert_eq!(bytes, chunks[0]);
    assert_eq!(peer, good.address);
    assert_eq!(bad.calls.load(Ordering::Relaxed), 1);
    assert_eq!(requests_left.load(Ordering::Relaxed), 7);
}

#[test]
fn absence_and_interrupted_io_do_not_quarantine_or_renew_the_original_budget() {
    for interrupted in [false, true] {
        let peer = Peer::start(move |_, call| {
            if call == 0 {
                if interrupted {
                    None
                } else {
                    Some(response(b"TCS1", None))
                }
            } else {
                Some(response(b"TCS1", Some(b"x")))
            }
        });
        let requests_left = AtomicU64::new(2);
        let responses = ResponseBudget::new(64);
        let transport = RequestContext {
            cancelled: None,
            timeout: Duration::from_secs(2),
            overall: Instant::now() + Duration::from_secs(10),
            requests_left: &requests_left,
            responses: &responses,
        };
        assert!(request(peer.address, 2, [1; 32], 1, &transport).is_err());
        assert!(!responses.is_quarantined(peer.address).unwrap());
        assert_eq!(
            request(peer.address, 2, [1; 32], 1, &transport).unwrap(),
            b"x"
        );
        assert_eq!(requests_left.load(Ordering::Relaxed), 0);
        assert_eq!(
            responses.received().unwrap(),
            if interrupted { 10 } else { 19 }
        );
    }
}

#[test]
fn rarest_observed_first_uses_real_pinned_chunks_and_one_original_budget() {
    let (dir, _path, manifest, chunks) = fixture();
    let order = Arc::new(Mutex::new(Vec::new()));
    let a = supplying_peer(manifest.clone(), chunks.clone(), 3, order.clone());
    let b = supplying_peer(manifest.clone(), chunks.clone(), 5, order.clone());
    let cache = CellStoreV1::open(&dir.path().join("consumer"), cache_config()).unwrap();
    cache
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    let output = dir.path().join("model.weights");
    let (_, report) = fetch_cell_rarest_first_to_file(
        &cache,
        manifest.id(),
        &[a.address, b.address],
        limits(),
        &output,
    )
    .unwrap();
    assert_eq!(*order.lock().unwrap(), [1, 2, 0]);
    assert_eq!(fs::read(output).unwrap(), chunks.concat());
    assert_eq!(report.connection_attempts, 5);
    assert_eq!(report.received_response_bytes, 2 * 10 + 3 * (9 + 16_384));
    assert_eq!(report.downloaded_chunks, 3);
    assert_eq!(report.rejected_responses, 0);
    assert_eq!(report.supplying_peers.len(), 2);
}

#[test]
fn availability_probe_exhaustion_cannot_reset_connections_or_publish_partial_output() {
    let (dir, _path, manifest, chunks) = fixture();
    let order = Arc::new(Mutex::new(Vec::new()));
    let a = supplying_peer(manifest.clone(), chunks.clone(), 3, order.clone());
    let b = supplying_peer(manifest.clone(), chunks, 5, order.clone());
    let cache = CellStoreV1::open(&dir.path().join("consumer"), cache_config()).unwrap();
    cache
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    let output = dir.path().join("must-not-publish");
    let mut bounded = limits();
    bounded.max_connections = 2;
    assert!(fetch_cell_rarest_first_to_file(
        &cache,
        manifest.id(),
        &[a.address, b.address],
        bounded,
        &output
    )
    .is_err());
    assert!(!output.exists());
    assert!(order.lock().unwrap().is_empty());
    assert_eq!(
        a.calls.load(Ordering::Relaxed) + b.calls.load(Ordering::Relaxed),
        2
    );
    for chunk in manifest.chunks() {
        assert!(cache.chunk(chunk.sha256).unwrap().is_none());
    }
}

#[test]
fn malformed_inventory_padding_is_quarantined_and_oversize_page_never_dials() {
    let bad = Peer::start(|_, _| Some(response(b"TIS1", Some(&[0b1000_0000]))));
    let requests_left = AtomicU64::new(2);
    let responses = ResponseBudget::new(64);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: Instant::now() + Duration::from_secs(10),
        requests_left: &requests_left,
        responses: &responses,
    };
    assert!(request_page(bad.address, [1; 32], 0, 257, &transport).is_err());
    assert_eq!(requests_left.load(Ordering::Relaxed), 2);
    assert!(request_page(bad.address, [1; 32], 0, 3, &transport).is_err());
    assert!(responses.is_quarantined(bad.address).unwrap());
    assert!(request_page(bad.address, [1; 32], 0, 3, &transport).is_err());
    assert_eq!(bad.calls.load(Ordering::Relaxed), 1);
    assert_eq!(requests_left.load(Ordering::Relaxed), 1);
    assert_eq!(responses.received().unwrap(), 10);
}

#[test]
fn explicit_real_inventory_server_and_existing_downloader_verify_the_whole_payload() {
    let (dir, path, manifest, chunks) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let server = thread::spawn(move || {
        serve_cells_bounded_with_availability(
            &listener,
            &path,
            &shutdown,
            CellServeLimitsV1 {
                request_timeout: Duration::from_secs(2),
                overall_timeout: Duration::from_secs(15),
                max_workers: 4,
                max_connections: 64,
                max_response_bytes: 8 * 1024 * 1024,
            },
        )
        .unwrap()
    });
    let cache = CellStoreV1::open(&dir.path().join("consumer"), cache_config()).unwrap();
    let output = dir.path().join("complete.weights");
    let result =
        fetch_cell_rarest_first_to_file(&cache, manifest.id(), &[address], limits(), &output);
    stop.store(true, Ordering::Relaxed);
    let served = server.join().unwrap();
    let (actual, report) = result.unwrap();
    assert_eq!(actual, manifest);
    assert_eq!(fs::read(output).unwrap(), chunks.concat());
    assert_eq!(report.connection_attempts, 5);
    assert_eq!(served.completed_requests, 5);
    assert_eq!(served.sent_response_bytes, report.received_response_bytes);
    assert_eq!(
        report.received_response_bytes,
        10 + manifest.encode().len() as u64 + 9 + 3 * (9 + 16_384)
    );
}

#[test]
fn zero_inventory_hints_cannot_hide_valid_chunks_from_the_original_fallback() {
    let (dir, _path, manifest, chunks) = fixture();
    let supplied_manifest = manifest.clone();
    let supplied_chunks = chunks.clone();
    let peer = Peer::start(move |query, _| {
        if &query[..4] == b"TCI1" {
            return Some(response(b"TIS1", Some(&[0])));
        }
        let index = supplied_manifest
            .chunks()
            .iter()
            .position(|chunk| chunk.sha256.as_slice() == &query[5..])
            .unwrap();
        Some(response(b"TCS1", Some(&supplied_chunks[index])))
    });
    let cache = CellStoreV1::open(&dir.path().join("consumer"), cache_config()).unwrap();
    cache
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    let (actual, report) =
        fetch_cell_rarest_first(&cache, manifest.id(), &[peer.address], limits()).unwrap();
    assert_eq!(actual, manifest);
    assert_eq!(report.connection_attempts, 4);
    assert_eq!(report.downloaded_chunks, 3);
    assert_eq!(report.rejected_responses, 0);
    cache.verify_complete(&manifest).unwrap();
}

#[test]
fn inventory_response_body_spends_the_last_byte_without_a_fresh_payload_allowance() {
    let (dir, _path, manifest, chunks) = fixture();
    let order = Arc::new(Mutex::new(Vec::new()));
    let a = supplying_peer(manifest.clone(), chunks.clone(), 3, order.clone());
    let b = supplying_peer(manifest.clone(), chunks, 5, order.clone());
    let cache = CellStoreV1::open(&dir.path().join("consumer"), cache_config()).unwrap();
    cache
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    let output = dir.path().join("must-not-publish");
    let mut bounded = limits();
    bounded.max_response_bytes = 19;
    assert!(matches!(
        fetch_cell_rarest_first_to_file(
            &cache,
            manifest.id(),
            &[a.address, b.address],
            bounded,
            &output
        ),
        Err(CellErrorV1::ResponseByteBudgetExhausted {
            received_response_bytes: 19,
            max_response_bytes: 19
        })
    ));
    assert!(!output.exists());
    assert!(order.lock().unwrap().is_empty());
    assert_eq!(
        a.calls.load(Ordering::Relaxed) + b.calls.load(Ordering::Relaxed),
        2
    );
}

#[test]
fn default_server_retains_legacy_namespace_and_inventory_failure_allows_byte_fallback() {
    let (dir, path, manifest, _) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let server = thread::spawn(move || {
        serve_cells_bounded(
            &listener,
            &path,
            &shutdown,
            CellServeLimitsV1 {
                request_timeout: Duration::from_secs(2),
                overall_timeout: Duration::from_secs(15),
                max_workers: 4,
                max_connections: 64,
                max_response_bytes: 8 * 1024 * 1024,
            },
        )
        .unwrap()
    });
    let cache = CellStoreV1::open(&dir.path().join("consumer"), cache_config()).unwrap();
    cache
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    let result = fetch_cell_rarest_first(&cache, manifest.id(), &[address], limits());
    stop.store(true, Ordering::Relaxed);
    let served = server.join().unwrap();
    let (_, report) = result.unwrap();
    assert_eq!(report.connection_attempts, 4);
    assert_eq!(report.downloaded_chunks, 3);
    assert_eq!(report.rejected_responses, 1);
    assert_eq!(served.completed_requests, 3);
    assert_eq!(served.accepted_connections, 4);
    assert_eq!(served.sent_response_bytes, report.received_response_bytes);
    cache.verify_complete(&manifest).unwrap();
}
