use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    thread,
};

use super::*;
use crate::cell::{
    version::tests::owner, version_content::tests::captured, CellCacheConfigV4, CellContextV1,
    CellFileRoleV1, CellManifestV1, CellVersionContentV2, CellVersionLoaderContextV1,
};

fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 8 * 1_048_576,
        max_logical_bytes: 4 * 1_048_576,
        max_chunk_rows: 128,
        max_manifest_rows: 32,
    }
}

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "bep52-peer-test".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}

fn limits() -> CellBep52PeerLimitsV1 {
    CellBep52PeerLimitsV1 {
        deadline: Instant::now() + Duration::from_secs(10),
        request_timeout: Duration::from_secs(2),
        max_connections: 8,
        max_received_bytes: 4 * 1_048_576,
        max_sent_bytes: 4 * 1_048_576,
        max_messages: 1000,
    }
}

fn session() -> CellBep52PeerSessionV1 {
    CellBep52PeerSessionV1::new([42; 32], limits()).unwrap()
}

fn fixture(
    bytes: &[u8],
) -> (
    tempfile::TempDir,
    PathBuf,
    CellManifestV1,
    CellBep52BindingV1,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("origin.sqlite");
    let input = dir.path().join("input");
    fs::write(&input, bytes).unwrap();
    let store = CellStoreV1::open(&path, config()).unwrap();
    let manifest = store.pack_file(&input, context(), 16_384).unwrap();
    let binding =
        CellBep52BindingV1::from_pinned_manifest(&manifest, manifest.id(), &context()).unwrap();
    (dir, path, manifest, binding)
}

#[derive(Debug, Eq, PartialEq)]
enum PeerOutcome {
    Connected,
    NoConnection,
}

struct PeerServer {
    cancelled: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<PeerOutcome>>,
}

impl PeerServer {
    fn stop_and_join(&mut self) -> thread::Result<PeerOutcome> {
        self.cancelled.store(true, Ordering::Release);
        self.worker.take().unwrap().join()
    }

    fn join(mut self) -> thread::Result<()> {
        assert_eq!(self.stop_and_join()?, PeerOutcome::Connected);
        Ok(())
    }

    // Only controls that explicitly permit pre-dial refusal use this outcome.
    fn finish_allowing_no_connection(mut self) -> thread::Result<PeerOutcome> {
        self.stop_and_join()
    }
}

impl Drop for PeerServer {
    fn drop(&mut self) {
        if self.worker.is_some() {
            let outcome = self.stop_and_join();
            // Always collect the peer on unwind, without causing a second panic.
            // A normally dropped positive fixture still requires its callback.
            if !thread::panicking() {
                assert_eq!(outcome.unwrap(), PeerOutcome::Connected);
            }
        }
    }
}

fn peer_with(task: impl FnOnce(TcpStream) + Send + 'static) -> (SocketAddr, PeerServer) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let accept_deadline = Instant::now() + Duration::from_secs(5);
    let worker = thread::spawn(move || {
        let stream = loop {
            // Drain an already queued connection before honoring cleanup.
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    // An interrupted accept does not establish an empty queue.
                    assert!(
                        Instant::now() < accept_deadline,
                        "test peer accept deadline exhausted"
                    );
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if worker_cancelled.load(Ordering::Acquire) {
                        return PeerOutcome::NoConnection;
                    }
                    assert!(
                        Instant::now() < accept_deadline,
                        "test peer accept deadline exhausted"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("test peer accept failed: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        task(stream);
        PeerOutcome::Connected
    });
    (
        address,
        PeerServer {
            cancelled,
            worker: Some(worker),
        },
    )
}

fn start_seed(path: &Path, binding: &CellBep52BindingV1) -> (SocketAddr, PeerServer) {
    let path = path.to_owned();
    let binding = binding.clone();
    peer_with(move |stream| {
        let store = CellStoreV1::open_read_only(&path).unwrap();
        let source =
            CellBep52SeedV1::prepare(&store, &binding, Instant::now() + Duration::from_secs(5))
                .unwrap();
        source
            .serve_connection(stream, *b"-CT0001-seed-peer001", &mut session())
            .unwrap();
    })
}

fn raw_send(stream: &mut TcpStream, bytes: &[u8]) {
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(bytes).unwrap();
}

fn raw_receive(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    let length = u32::from_be_bytes(header) as usize;
    assert!(length <= 17_408);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    body
}

// This fixture deliberately constructs wire bytes independently of the adapter
// encoders and uses ut_metadata=17, exercising the peer-local BEP10 mapping.
fn raw_peer_handshake(stream: &mut TcpStream, binding: &CellBep52BindingV1, metadata_size: usize) {
    let mut header = [0; 68];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(&header[1..20], b"BitTorrent protocol");
    assert_eq!(&header[28..48], &binding.info_hash()[..20]);
    header[48..].copy_from_slice(b"-IN0001-independent1");
    stream.write_all(&header).unwrap();
    let body = format!("d1:md11:ut_metadatai17ee13:metadata_sizei{metadata_size}ee");
    let mut wire = vec![20, 0];
    wire.extend_from_slice(body.as_bytes());
    raw_send(stream, &wire);
}

fn raw_metadata(stream: &mut TcpStream, binding: &CellBep52BindingV1, corrupt: bool) {
    assert_eq!(raw_receive(stream), b"\x14\x00d1:md11:ut_metadatai1eee");
    assert_eq!(raw_receive(stream), b"\x14\x11d8:msg_typei0e5:piecei0ee");
    let mut info = binding.info_bytes();
    if corrupt {
        *info.last_mut().unwrap() ^= 1;
    }
    let mut response = vec![20, 1];
    response.extend_from_slice(
        format!("d8:msg_typei1e5:piecei0e10:total_sizei{}ee", info.len()).as_bytes(),
    );
    response.extend_from_slice(&info);
    raw_send(stream, &response);
}

fn content_pin(content: &CellVersionContentV2) -> PinnedCellVersionContentV2<'_> {
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    content
        .pin_for_owner(
            &CellVersionLoaderContextV1 {
                commitment: content.version().commitment(),
                model: &model,
                environment: &environment,
            },
            content.commitment(),
        )
        .unwrap()
}

fn first_content_binding(content: &CellVersionContentV2) -> CellBep52BindingV1 {
    let manifest = &content.version().manifests()[0];
    CellBep52BindingV1::from_pinned_manifest(manifest, manifest.id(), manifest.context()).unwrap()
}

// Keep all original TCM1 locators and declarations unchanged. The caller pins
// this intentionally inconsistent record independently, so the test reaches
// actual strong-byte validation instead of merely rejecting a changed root.
fn changed_content_digest(content: &CellVersionContentV2, chunk: bool) -> CellVersionContentV2 {
    let mut wire = content.encode();
    let metadata_bytes = u32::from_be_bytes(wire[4..8].try_into().unwrap()) as usize;
    let first_payload = 8 + metadata_bytes + 2 + 32;
    let at = if chunk {
        first_payload + 64 + 4
    } else {
        first_payload
    };
    wire[at] ^= 1;
    CellVersionContentV2::decode(&wire).unwrap()
}

#[test]
fn strong_content_wrong_owner_pin_or_manifest_refuses_before_socket_and_cas() {
    let (dir, _origin, content) = captured();
    let model = owner(content.version().model().closure(), CellFileRoleV1::Base);
    let environment = owner(
        content.version().environment(),
        CellFileRoleV1::Configuration,
    );
    let mut wrong_pin = content.commitment();
    wrong_pin[63] ^= 1;
    assert!(content
        .pin_for_owner(
            &CellVersionLoaderContextV1 {
                commitment: content.version().commitment(),
                model: &model,
                environment: &environment,
            },
            wrong_pin,
        )
        .is_err());
    let (_foreign_dir, _path, _manifest, foreign) = fixture(b"not in the pinned full version");
    let pinned = content_pin(&content);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let store = CellStoreV1::open(&dir.path().join("consumer.sqlite"), config()).unwrap();
    let before = store.cache_usage().unwrap();
    let mut budget = session();
    assert!(fetch_cell_bep52_with_content(
        &store,
        &foreign,
        &pinned,
        &[listener.local_addr().unwrap()],
        [7; 20],
        &mut budget,
    )
    .is_err());
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    assert_eq!(budget.usage(), &CellBep52PeerUsageV1::default());
    assert_eq!(store.cache_usage().unwrap(), before);
}

#[test]
fn tcp_strong_chunk_mismatch_refuses_publication_and_cache_hit_without_refunding() {
    let (dir, origin, content) = captured();
    let binding = first_content_binding(&content);
    let changed = changed_content_digest(&content, true);
    let pinned = content_pin(&changed);
    let consumer = CellStoreV1::open(&dir.path().join("consumer.sqlite"), config()).unwrap();
    let (address, server) = start_seed(&dir.path().join("cache.sqlite"), &binding);
    let mut budget = session();
    let deadline = budget.deadline();
    assert!(fetch_cell_bep52_with_content(
        &consumer,
        &binding,
        &pinned,
        &[address],
        [7; 20],
        &mut budget,
    )
    .is_err());
    server.join().unwrap();
    // Independently pinned manifest metadata can remain; no payload chunk was
    // published, despite a complete real TCP piece with a valid legacy hash.
    assert_eq!(consumer.cache_usage().unwrap().chunk_rows, 0);
    assert_eq!(consumer.cache_usage().unwrap().manifest_rows, 1);
    assert_eq!(budget.usage().connection_attempts, 1);
    assert_eq!(budget.usage().refused_connections, 1);
    assert_eq!(budget.usage().completed_fetches, 0);
    assert!(budget.usage().received_bytes >= u64::from(binding.manifest().chunks()[0].size));
    assert!(budget.refusals()[0].1.contains("content SHA512 chunk"));
    let spent = budget.usage().clone();
    assert!(fetch_cell_bep52_with_content(
        &consumer,
        &binding,
        &pinned,
        &[address],
        [7; 20],
        &mut budget,
    )
    .is_err());
    assert_eq!(budget.usage(), &spent);
    assert_eq!(budget.deadline(), deadline);

    // A valid legacy CAS hit must not bypass the same strong chunk check.
    let chunk = &binding.manifest().chunks()[0];
    consumer
        .put_chunk(chunk, &origin.chunk(chunk.sha256).unwrap().unwrap())
        .unwrap();
    let cached_before = consumer.cache_usage().unwrap();
    let mut cached_session = session();
    assert!(matches!(
        fetch_cell_bep52_with_content(
            &consumer,
            &binding,
            &pinned,
            &[],
            [7; 20],
            &mut cached_session,
        ),
        Err(CellErrorV1::Invalid("content SHA512 chunk")),
    ));
    assert_eq!(cached_session.usage(), &CellBep52PeerUsageV1::default());
    assert_eq!(consumer.cache_usage().unwrap(), cached_before);
}

#[test]
fn tcp_strong_content_fetch_reads_actual_payload_and_cached_resume_under_same_session() {
    let (dir, origin, content) = captured();
    let binding = first_content_binding(&content);
    let pinned = content_pin(&content);
    let consumer = CellStoreV1::open(&dir.path().join("consumer.sqlite"), config()).unwrap();
    let (address, server) = start_seed(&dir.path().join("cache.sqlite"), &binding);
    let mut budget = session();
    let deadline = budget.deadline();
    let report = fetch_cell_bep52_with_content(
        &consumer,
        &binding,
        &pinned,
        &[address],
        [7; 20],
        &mut budget,
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(report.downloaded_bytes, binding.manifest().size());
    assert_eq!(report.downloaded_chunks, binding.manifest().chunks().len());
    assert_eq!(report.supplying_peers, BTreeSet::from([address]));
    assert_eq!(budget.usage().completed_fetches, 1);
    let mut actual = Sha512::new();
    actual.update(b"TRNM/Cell/PayloadContent/v2\0");
    actual.update(binding.manifest().size().to_be_bytes());
    for chunk in binding.manifest().chunks() {
        let bytes = consumer.chunk(chunk.sha256).unwrap().unwrap();
        assert_eq!(bytes, origin.chunk(chunk.sha256).unwrap().unwrap());
        actual.update(&bytes);
    }
    assert_eq!(
        <[u8; 64]>::from(actual.finalize()),
        pinned.payload_sha512(binding.manifest_id()).unwrap()
    );
    let spent = budget.usage().clone();
    let cached =
        fetch_cell_bep52_with_content(&consumer, &binding, &pinned, &[], [7; 20], &mut budget)
            .unwrap();
    assert_eq!(cached.cached_chunks, binding.manifest().chunks().len());
    assert_eq!(cached.downloaded_bytes, 0);
    assert_eq!(budget.usage().received_bytes, spent.received_bytes);
    assert_eq!(
        budget.usage().connection_attempts,
        spent.connection_attempts
    );
    assert_eq!(budget.usage().completed_fetches, 2);
    assert_eq!(budget.deadline(), deadline);
}

#[test]
fn tcp_strong_full_payload_mismatch_refuses_success_after_valid_chunk_publication() {
    let (dir, _origin, content) = captured();
    let binding = first_content_binding(&content);
    let changed = changed_content_digest(&content, false);
    let pinned = content_pin(&changed);
    let consumer = CellStoreV1::open(&dir.path().join("consumer.sqlite"), config()).unwrap();
    let (address, server) = start_seed(&dir.path().join("cache.sqlite"), &binding);
    let mut budget = session();
    assert!(matches!(
        fetch_cell_bep52_with_content(
            &consumer,
            &binding,
            &pinned,
            &[address],
            [7; 20],
            &mut budget,
        ),
        Err(CellErrorV1::Invalid("BEP52 complete strong payload digest")),
    ));
    server.join().unwrap();
    assert_eq!(budget.usage().completed_fetches, 0);
    assert_eq!(budget.usage().connection_attempts, 1);
    assert!(budget.usage().received_bytes > binding.manifest().size());
    assert_eq!(consumer.cache_usage().unwrap().chunk_rows, 3);
    consumer.verify_complete(binding.manifest()).unwrap();
}

#[test]
fn tcp_metadata_payload_complete_cas_resume_and_same_byte_dedup() {
    let mut bytes = vec![b'A'; 16_384];
    bytes.extend(vec![b'B'; 16_384]);
    bytes.extend(vec![b'A'; 16_384]);
    bytes.extend([b'C'; 97]);
    let (dir, path, manifest, binding) = fixture(&bytes);
    let consumer = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    consumer
        .put_chunk(&manifest.chunks()[0], &bytes[..16_384])
        .unwrap();
    let (address, server) = start_seed(&path, &binding);
    let mut budget = session();
    let deadline = budget.deadline();
    let report = fetch_cell_bep52(
        &consumer,
        &binding,
        &[address],
        *b"-CT0001-read-peer001",
        &mut budget,
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(report.cached_chunks, 2);
    assert_eq!(report.downloaded_chunks, 2);
    assert_eq!(report.downloaded_bytes, 16_384 + 97);
    assert_eq!(report.supplying_peers, BTreeSet::from([address]));
    assert_eq!(budget.usage().connection_attempts, 1);
    assert_eq!(budget.usage().refused_connections, 0);
    assert!(budget.usage().received_bytes > report.downloaded_bytes);
    assert_eq!(budget.deadline(), deadline);
    let output = dir.path().join("model.weights");
    consumer
        .materialize_until(&manifest, &output, deadline)
        .unwrap();
    assert_eq!(fs::read(output).unwrap(), bytes);
    let previous = budget.usage().clone();
    let cached = fetch_cell_bep52(
        &consumer,
        &binding,
        &[],
        *b"-CT0001-read-peer001",
        &mut budget,
    )
    .unwrap();
    assert_eq!(cached.cached_chunks, 4);
    assert_eq!(cached.downloaded_bytes, 0);
    assert_eq!(budget.usage().received_bytes, previous.received_bytes);
    assert_eq!(
        budget.usage().connection_attempts,
        previous.connection_attempts
    );
    assert_eq!(budget.usage().completed_fetches, 2);
}

#[test]
fn tcp_independent_wire_dynamic_metadata_id_and_short_final_piece() {
    let bytes = b"an independent TCP fixture";
    let (dir, _, manifest, binding) = fixture(bytes);
    let reference = binding.clone();
    let (address, server) = peer_with(move |mut stream| {
        raw_peer_handshake(&mut stream, &reference, reference.info_bytes().len());
        raw_metadata(&mut stream, &reference, false);
        assert_eq!(raw_receive(&mut stream), [2]);
        raw_send(&mut stream, &[1]);
        let request = raw_receive(&mut stream);
        assert_eq!(request[0], 6);
        assert_eq!(&request[1..9], &[0; 8]);
        assert_eq!(
            u32::from_be_bytes(request[9..].try_into().unwrap()),
            bytes.len() as u32
        );
        let mut piece = vec![7];
        piece.extend([0; 8]);
        piece.extend(bytes);
        raw_send(&mut stream, &piece);
        assert_eq!(raw_receive(&mut stream), [3]);
    });
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let report = fetch_cell_bep52(&store, &binding, &[address], [7; 20], &mut session()).unwrap();
    server.join().unwrap();
    assert_eq!(report.downloaded_bytes, bytes.len() as u64);
    store.verify_complete(&manifest).unwrap();
}

#[test]
fn tcp_wrong_full_metadata_with_matching_handshake_prefix_is_refused() {
    let (dir, _, manifest, binding) = fixture(b"same 20 byte handshake is not metadata authority");
    let reference = binding.clone();
    let (address, server) = peer_with(move |mut stream| {
        raw_peer_handshake(&mut stream, &reference, reference.info_bytes().len());
        raw_metadata(&mut stream, &reference, true);
    });
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let mut budget = session();
    assert!(fetch_cell_bep52(&store, &binding, &[address], [7; 20], &mut budget).is_err());
    server.join().unwrap();
    assert_eq!(budget.usage().refused_connections, 1);
    assert_eq!(budget.usage().completed_fetches, 0);
    assert!(budget.usage().received_bytes > 68);
    assert!(store.chunk(manifest.chunks()[0].sha256).unwrap().is_none());
}

#[test]
fn tcp_metadata_size_bomb_is_refused_before_a_metadata_request() {
    let (dir, _, _, binding) = fixture(b"metadata bomb");
    let reference = binding.clone();
    let (address, server) = peer_with(move |mut stream| {
        raw_peer_handshake(&mut stream, &reference, 2_147_483_647);
        assert_eq!(
            raw_receive(&mut stream),
            b"\x14\x00d1:md11:ut_metadatai1eee"
        );
        let mut bytes = [0; 1];
        assert_eq!(stream.read(&mut bytes).unwrap_or(0), 0);
    });
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let mut budget = session();
    assert!(fetch_cell_bep52(&store, &binding, &[address], [7; 20], &mut budget).is_err());
    server.join().unwrap();
    assert!(budget.usage().received_bytes < 256);
    assert_eq!(budget.usage().refused_connections, 1);
}

#[test]
fn tcp_oversize_frame_rejects_after_four_byte_header_without_body_allocation() {
    let (dir, _, _, binding) = fixture(b"frame bomb");
    let reference = binding.clone();
    let (address, server) = peer_with(move |mut stream| {
        let mut header = [0; 68];
        stream.read_exact(&mut header).unwrap();
        stream.write_all(&header).unwrap();
        assert_eq!(&header[28..48], &reference.info_hash()[..20]);
        stream.write_all(&u32::MAX.to_be_bytes()).unwrap();
        let _ = raw_receive(&mut stream);
    });
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let mut budget = session();
    assert!(fetch_cell_bep52(&store, &binding, &[address], [7; 20], &mut budget).is_err());
    server.join().unwrap();
    assert_eq!(budget.usage().received_bytes, 72);
    assert_eq!(budget.usage().refused_connections, 1);
}

#[test]
fn tcp_partial_header_failure_retains_actual_received_bytes() {
    let (dir, _, _, binding) = fixture(b"truncation");
    let (address, server) = peer_with(move |mut stream| {
        let mut header = [0; 68];
        stream.read_exact(&mut header).unwrap();
        stream.write_all(&header).unwrap();
        let _ = raw_receive(&mut stream);
        stream.write_all(&[0, 0]).unwrap();
    });
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let mut budget = session();
    assert!(fetch_cell_bep52(&store, &binding, &[address], [7; 20], &mut budget).is_err());
    server.join().unwrap();
    assert_eq!(budget.usage().received_bytes, 70);
}

#[test]
fn tcp_exact_byte_budget_and_failed_peer_quarantine_survive_continuation() {
    let (dir, _, _, binding) = fixture(b"byte budget");
    let reference = binding.clone();
    let (address, server) = peer_with(move |mut stream| {
        raw_peer_handshake(&mut stream, &reference, reference.info_bytes().len());
        let _ = stream.read(&mut [0; 100]);
    });
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let mut bounds = limits();
    bounds.max_received_bytes = 70;
    let mut budget = CellBep52PeerSessionV1::new([9; 32], bounds).unwrap();
    assert!(fetch_cell_bep52(&store, &binding, &[address], [7; 20], &mut budget).is_err());
    server.join().unwrap();
    assert_eq!(budget.usage().received_bytes, 70);
    let before = budget.usage().clone();
    assert!(fetch_cell_bep52(&store, &binding, &[address], [7; 20], &mut budget).is_err());
    assert_eq!(*budget.usage(), before);
}

#[test]
fn tcp_keepalive_flood_spends_original_message_budget() {
    let (dir, _, _, binding) = fixture(b"keepalives");
    let (address, server) = peer_with(move |mut stream| {
        let mut header = [0; 68];
        stream.read_exact(&mut header).unwrap();
        stream.write_all(&header).unwrap();
        let _ = raw_receive(&mut stream);
        let _ = stream.write_all(&[0; 200]);
    });
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let mut bounds = limits();
    bounds.max_messages = 4;
    let mut budget = CellBep52PeerSessionV1::new([9; 32], bounds).unwrap();
    assert!(fetch_cell_bep52(&store, &binding, &[address], [7; 20], &mut budget).is_err());
    server.join().unwrap();
    assert_eq!(
        budget.usage().received_messages + budget.usage().sent_messages,
        4
    );
    assert_eq!(budget.usage().received_bytes, 68 + 3 * 4);
}

#[test]
fn tcp_slow_fragmented_handshake_does_not_renew_original_deadline() {
    let (dir, _, _, binding) = fixture(b"slow peer");
    let (address, server) = peer_with(move |mut stream| {
        let mut header = [0; 68];
        stream.read_exact(&mut header).unwrap();
        for byte in header {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    });
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let mut bounds = limits();
    bounds.deadline = Instant::now() + Duration::from_millis(120);
    let mut budget = CellBep52PeerSessionV1::new([9; 32], bounds).unwrap();
    let started = Instant::now();
    assert!(fetch_cell_bep52(&store, &binding, &[address], [7; 20], &mut budget).is_err());
    assert!(started.elapsed() < Duration::from_millis(600));
    assert_eq!(budget.deadline(), bounds.deadline);
    assert!(budget.usage().received_bytes < 68);
    match server.finish_allowing_no_connection().unwrap() {
        PeerOutcome::Connected => assert_eq!(budget.usage().sent_bytes, 68),
        PeerOutcome::NoConnection => {
            // Full-entry cache work can consume the original budget before
            // dialing. This outcome does not claim a fragmented handshake ran.
            assert_eq!(budget.usage().sent_bytes, 0);
            assert_eq!(budget.usage().received_bytes, 0);
        }
    }
}

#[test]
fn tcp_slow_fragmented_fetch_peer_preserves_original_deadline() {
    let (dir, _, _, binding) = fixture(b"slow peer transport");
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    store
        .put_manifest(binding.manifest_id(), &binding.manifest().encode())
        .unwrap();
    let mut missing = binding
        .manifest()
        .chunks()
        .iter()
        .map(|chunk| chunk.sha256)
        .collect();
    let mut report = CellBep52FetchReportV1 {
        manifest_id: binding.manifest_id(),
        info_hash: binding.info_hash(),
        payload_sha256: binding.manifest().payload_sha256(),
        payload_bytes: binding.manifest().size(),
        cached_chunks: 0,
        downloaded_chunks: 0,
        downloaded_bytes: 0,
        supplying_peers: BTreeSet::new(),
    };
    let (address, server) = peer_with(move |mut stream| {
        let mut header = [0; 68];
        stream.read_exact(&mut header).unwrap();
        for byte in header {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    });
    // Select the real transport phase after fixture/cache preparation. The
    // original deadline is created once and still covers connect/write/read.
    let mut bounds = limits();
    bounds.deadline = Instant::now() + Duration::from_millis(120);
    let mut budget = CellBep52PeerSessionV1::new([9; 32], bounds).unwrap();
    let started = Instant::now();
    budget.connection().unwrap();
    assert!(fetch_peer(
        &store,
        FetchPlan {
            binding: &binding,
            content: None,
        },
        address,
        [7; 20],
        &mut budget,
        &mut missing,
        &mut report,
    )
    .is_err());
    assert!(started.elapsed() < Duration::from_millis(600));
    assert!(Instant::now() >= bounds.deadline);
    assert_eq!(budget.deadline(), bounds.deadline);
    assert_eq!(budget.usage().connection_attempts, 1);
    assert_eq!(budget.usage().sent_bytes, 68);
    assert!((1..68).contains(&budget.usage().received_bytes));
    assert_eq!(budget.usage().completed_fetches, 0);
    server.join().unwrap();
}

#[test]
fn tcp_peer_without_connection_has_bounded_cleanup() {
    let (dir, _, _, binding) = fixture(b"no peer connection");
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let called = Arc::new(AtomicBool::new(false));
    let peer_called = Arc::clone(&called);
    let (address, server) = peer_with(move |_| {
        peer_called.store(true, Ordering::Release);
    });
    let mut bounds = limits();
    bounds.deadline = Instant::now() + Duration::from_millis(120);
    let mut budget = CellBep52PeerSessionV1::new([9; 32], bounds).unwrap();
    thread::sleep(bounds.deadline.saturating_duration_since(Instant::now()));
    assert!(Instant::now() >= bounds.deadline);
    assert!(fetch_cell_bep52(&store, &binding, &[address], [7; 20], &mut budget).is_err());
    assert_eq!(budget.deadline(), bounds.deadline);
    assert_eq!(budget.usage().connection_attempts, 0);
    assert_eq!(budget.usage().sent_bytes, 0);
    assert_eq!(budget.usage().received_bytes, 0);
    let cleanup_started = Instant::now();
    assert_eq!(
        server.finish_allowing_no_connection().unwrap(),
        PeerOutcome::NoConnection
    );
    assert!(cleanup_started.elapsed() < Duration::from_millis(600));
    assert!(!called.load(Ordering::Acquire));
}

#[test]
fn cancellation_latches_and_refuses_cache_writes_before_dial() {
    let (dir, _, manifest, binding) = fixture(b"cancelled");
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let mut budget = session();
    let flag = budget.cancellation_handle();
    flag.store(true, Ordering::Release);
    assert!(fetch_cell_bep52(&store, &binding, &[], [7; 20], &mut budget).is_err());
    flag.store(false, Ordering::Release);
    assert!(fetch_cell_bep52(&store, &binding, &[], [7; 20], &mut budget).is_err());
    assert!(store.manifest(manifest.id()).unwrap().is_none());
    assert_eq!(budget.usage().connection_attempts, 0);
}

#[test]
fn tcp_bad_piece_then_next_peer_resumes_with_failure_bytes_in_same_reservation() {
    let mut bytes = vec![b'A'; 16_384];
    bytes.extend([b'B'; 57]);
    let (dir, path, manifest, binding) = fixture(&bytes);
    let reference = binding.clone();
    let payload = bytes.clone();
    let (bad_address, bad_server) = peer_with(move |mut stream| {
        raw_peer_handshake(&mut stream, &reference, reference.info_bytes().len());
        raw_metadata(&mut stream, &reference, false);
        assert_eq!(raw_receive(&mut stream), [2]);
        raw_send(&mut stream, &[1]);
        let first = raw_receive(&mut stream);
        assert_eq!(read_u32(&first[1..5]), 0);
        let mut piece = vec![7];
        piece.extend([0; 8]);
        piece.extend(&payload[..16_384]);
        raw_send(&mut stream, &piece);
        let second = raw_receive(&mut stream);
        assert_eq!(read_u32(&second[1..5]), 1);
        let mut piece = vec![7];
        piece.extend(1u32.to_be_bytes());
        piece.extend([0; 4]);
        piece.extend([b'X'; 57]);
        raw_send(&mut stream, &piece);
    });
    let (good_address, good_server) = start_seed(&path, &binding);
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let mut budget = session();
    let report = fetch_cell_bep52(
        &store,
        &binding,
        &[bad_address, good_address],
        [7; 20],
        &mut budget,
    )
    .unwrap();
    bad_server.join().unwrap();
    good_server.join().unwrap();
    assert_eq!(report.downloaded_bytes, bytes.len() as u64);
    assert_eq!(report.supplying_peers.len(), 2);
    assert_eq!(budget.usage().connection_attempts, 2);
    assert_eq!(budget.usage().refused_connections, 1);
    assert!(budget.usage().received_bytes > bytes.len() as u64 + 57);
    store.verify_complete(&manifest).unwrap();
}

#[test]
fn tcp_unsolicited_piece_never_enters_cache() {
    let (dir, _, manifest, binding) = fixture(b"unsolicited");
    let reference = binding.clone();
    let (address, server) = peer_with(move |mut stream| {
        raw_peer_handshake(&mut stream, &reference, reference.info_bytes().len());
        raw_metadata(&mut stream, &reference, false);
        assert_eq!(raw_receive(&mut stream), [2]);
        let mut piece = vec![7];
        piece.extend([0; 8]);
        piece.extend(b"unsolicited");
        raw_send(&mut stream, &piece);
    });
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let mut budget = session();
    assert!(fetch_cell_bep52(&store, &binding, &[address], [7; 20], &mut budget).is_err());
    server.join().unwrap();
    assert!(store.chunk(manifest.chunks()[0].sha256).unwrap().is_none());
    assert_eq!(budget.usage().refused_connections, 1);
}

#[test]
fn seed_hash_wire_covers_padding_proofs_and_rejects_wrong_roots() {
    let mut bytes = vec![b'A'; 16_384];
    bytes.extend(vec![b'B'; 16_384]);
    bytes.push(b'C');
    let (dir, path, manifest, binding) = fixture(&bytes);
    let (address, server) = start_seed(&path, &binding);
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(&handshake(&binding, [8; 20])).unwrap();
    let mut header = [0; 68];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(raw_receive(&mut stream)[..2], [20, 0]);
    assert_eq!(raw_receive(&mut stream), [5, 0xe0]);
    raw_send(&mut stream, b"\x14\x00d1:md11:ut_metadatai17eee");
    raw_send(&mut stream, b"\x14\x01d8:msg_typei0e5:piecei0ee");
    let metadata = raw_receive(&mut stream);
    assert_eq!(metadata[..2], [20, 17]);
    let mut query = vec![21];
    query.extend(binding.pieces_root());
    query.extend(0u32.to_be_bytes());
    query.extend(0u32.to_be_bytes());
    query.extend(2u32.to_be_bytes());
    query.extend(1u32.to_be_bytes());
    raw_send(&mut stream, &query);
    let response = raw_receive(&mut stream);
    assert_eq!(response[0], 22);
    assert_eq!(&response[1..49], &query[1..]);
    assert_eq!(&response[49..81], &manifest.chunks()[0].sha256);
    assert_eq!(&response[81..113], &manifest.chunks()[1].sha256);
    let mut pair = Sha256::new();
    pair.update(manifest.chunks()[2].sha256);
    pair.update([0; 32]);
    assert_eq!(&response[113..145], &<[u8; 32]>::from(pair.finalize()));
    query[37..41].copy_from_slice(&2u32.to_be_bytes());
    raw_send(&mut stream, &query);
    let response = raw_receive(&mut stream);
    assert_eq!(&response[49..81], &manifest.chunks()[2].sha256);
    assert_eq!(&response[81..113], &[0; 32]);
    query[1] ^= 1;
    raw_send(&mut stream, &query);
    let response = raw_receive(&mut stream);
    query[0] = 23;
    assert_eq!(response, query);
    stream.shutdown(Shutdown::Both).unwrap();
    server.join().unwrap();
    drop(dir);
}

#[test]
fn full_payload_digest_remains_mandatory_even_for_all_valid_chunk_hashes() {
    let (dir, path, manifest, _) = fixture(b"chunk is valid");
    let wrong = CellManifestV1::new(
        context(),
        manifest.size(),
        [99; 32],
        16_384,
        manifest.chunks().to_vec(),
    )
    .unwrap();
    let binding = CellBep52BindingV1::from_pinned_manifest(&wrong, wrong.id(), &context()).unwrap();
    let store = CellStoreV1::open(&path, config()).unwrap();
    let mut budget = session();
    assert!(fetch_cell_bep52(&store, &binding, &[], [8; 20], &mut budget).is_err());
    assert_eq!(budget.usage().completed_fetches, 0);
    assert!(
        CellBep52SeedV1::prepare(&store, &binding, Instant::now() + Duration::from_secs(1))
            .is_err()
    );
    drop(dir);
}

#[test]
fn malformed_bencode_depth_duplicate_integer_and_size_controls() {
    for bytes in [
        b"d1:ai1e1:ai2ee".as_slice(),
        b"d1:bi1e1:ai2ee",
        b"i-0e",
        b"i01e",
        b"i+1e",
        b"i18446744073709551616e",
        b"03:abc",
        b"5:abc",
        b"lllllllllli1eeeeeeeeeee",
    ] {
        assert!(decode(bytes).is_err(), "accepted {:?}", bytes);
    }
    assert!(parse_extension_handshake(b"d1:md11:ut_metadatai1e6:ut_pexi1eee").is_err());
    assert!(parse_extension_handshake(b"d1:md11:ut_metadatai256eee").is_err());
    assert_eq!(
        parse_extension_handshake(b"d1:md11:ut_metadatai0eee").unwrap(),
        (None, None)
    );
    assert!(parse_extension_handshake(b"d1:md11:ut_metadatai17eeeextra").is_err());
}

#[test]
fn bitfield_have_and_wire_shape_bounds() {
    let mut state = PeerState::new(3);
    assert!(state.control(&[5, 0xe1]).is_err());
    assert!(state.control(&[5, 0xe0, 0]).is_err());
    state.control(&[5, 0x80]).unwrap();
    assert!(state.known_absent(1));
    state.control(&[4, 0, 0, 0, 1]).unwrap();
    assert!(!state.known_absent(1));
    assert!(state.control(&[5, 0xe0]).is_err());
    assert!(state.control(&[4, 0, 0, 0, 3]).is_err());
    assert!(state.control(&[20]).is_err());
    assert!(state.control(&[1, 0]).is_err());
}

#[test]
fn zero_receive_reservation_refuses_before_dial_and_retains_no_failure_story() {
    let (dir, _, _, binding) = fixture(b"no receive reservation");
    let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
    let mut bounds = limits();
    bounds.max_received_bytes = 0;
    let mut budget = CellBep52PeerSessionV1::new([9; 32], bounds).unwrap();
    assert!(fetch_cell_bep52(
        &store,
        &binding,
        &["127.0.0.1:1".parse().unwrap()],
        [7; 20],
        &mut budget
    )
    .is_err());
    assert_eq!(budget.usage().connection_attempts, 0);
    assert_eq!(budget.usage().received_bytes, 0);
    assert_eq!(budget.usage().sent_bytes, 0);
    assert!(budget.refusals().is_empty());
}

#[test]
fn tcp_wrong_piece_index_begin_and_length_are_refused_and_recorded() {
    for case in 0..3 {
        let (dir, _, manifest, binding) = fixture(b"correlation");
        let reference = binding.clone();
        let (address, server) = peer_with(move |mut stream| {
            raw_peer_handshake(&mut stream, &reference, reference.info_bytes().len());
            raw_metadata(&mut stream, &reference, false);
            assert_eq!(raw_receive(&mut stream), [2]);
            raw_send(&mut stream, &[1]);
            assert_eq!(raw_receive(&mut stream)[0], 6);
            let mut piece = vec![7];
            piece.extend([0; 8]);
            piece.extend(b"correlation");
            match case {
                0 => piece[4] = 1,
                1 => piece[8] = 1,
                _ => piece.push(0),
            }
            raw_send(&mut stream, &piece);
        });
        let store = CellStoreV1::open(&dir.path().join("consumer"), config()).unwrap();
        let mut budget = session();
        assert!(fetch_cell_bep52(&store, &binding, &[address], [7; 20], &mut budget).is_err());
        server.join().unwrap();
        assert!(store.chunk(manifest.chunks()[0].sha256).unwrap().is_none());
        assert_eq!(budget.refusals().len(), 1);
        assert_eq!(budget.refusals()[0].0, address);
        assert!(budget.refusals()[0]
            .1
            .contains(if case == 2 { "length" } else { "correlation" }));
    }
}
