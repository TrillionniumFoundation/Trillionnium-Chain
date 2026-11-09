use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{atomic::Ordering, mpsc},
    thread,
};

use super::*;
use crate::cell::{
    CellBep52PeerLimitsV1, CellCacheConfigV4, CellContextV1, CellManifestV1, MAX_CHUNK_BYTES,
};

struct Fixture {
    directory: tempfile::TempDir,
    cache: PathBuf,
    bytes: Vec<u8>,
    binding: CellBep52StorageBindingV2,
}

fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 64 << 20,
        max_logical_bytes: 48 << 20,
        max_chunk_rows: 512,
        max_manifest_rows: 32,
    }
}

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "bep52-storage-peer-v2-test".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}

fn limits() -> CellBep52PeerLimitsV1 {
    CellBep52PeerLimitsV1 {
        deadline: Instant::now() + Duration::from_secs(30),
        request_timeout: Duration::from_secs(5),
        max_connections: 4,
        max_received_bytes: 32 << 20,
        max_sent_bytes: 32 << 20,
        max_messages: 4000,
    }
}

fn read_limits(binding: &CellBep52StorageBindingV2, deadline: Instant) -> CellReleaseLimitsV1 {
    CellReleaseLimitsV1 {
        max_payload_bytes: binding.manifest().size(),
        max_chunks: binding.manifest().chunks().len() as u64,
        deadline,
    }
}

fn fixture(length: usize, chunk_bytes: u32) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let cache = directory.path().join("source.sqlite");
    let input = directory.path().join("source.bin");
    let bytes: Vec<_> = (0..length)
        .map(|i| ((i * 17 + i / 16384) % 251) as u8)
        .collect();
    fs::write(&input, &bytes).unwrap();
    let store = CellStoreV1::open(&cache, config()).unwrap();
    let manifest = store.pack_file(&input, context(), chunk_bytes).unwrap();
    fs::remove_file(input).unwrap();
    let binding = CellBep52StorageBindingV2::from_pinned_store(
        &manifest,
        manifest.id(),
        &context(),
        &store,
        CellReleaseLimitsV1 {
            max_payload_bytes: manifest.size(),
            max_chunks: manifest.chunks().len() as u64,
            deadline: limits().deadline,
        },
    )
    .unwrap();
    Fixture {
        directory,
        cache,
        bytes,
        binding,
    }
}

fn start_seed(
    path: &Path,
    binding: &CellBep52StorageBindingV2,
    limits: CellBep52PeerLimitsV1,
) -> (SocketAddr, thread::JoinHandle<CellResultV1<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let path = path.to_owned();
    let binding = binding.clone();
    let (ready, receive_ready) = mpsc::channel();
    let worker = thread::spawn(move || {
        let store = CellStoreV1::open_read_only(&path)?;
        let seed = CellBep52StorageSeedV2::prepare(
            &store,
            &binding,
            read_limits(&binding, limits.deadline),
        )?;
        ready.send(()).unwrap();
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    check_deadline(limits.deadline)?;
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error.into()),
            }
        };
        let mut session = CellBep52PeerSessionV1::new([91; 32], limits)?;
        seed.serve_connection(stream, *b"-CV2001-seed-peer001", &mut session)
    });
    receive_ready
        .recv_timeout(limits.deadline.saturating_duration_since(Instant::now()))
        .unwrap();
    (address, worker)
}

#[test]
fn native_tcp_4mib_pieces_use_16k_requests_and_preserve_two_original_cache_rows() {
    let f = fixture(MAX_CHUNK_BYTES as usize + 251, MAX_CHUNK_BYTES);
    let reservation = limits();
    let (address, worker) = start_seed(&f.cache, &f.binding, reservation);
    let destination =
        CellStoreV1::open(&f.directory.path().join("receiver.sqlite"), config()).unwrap();
    let mut session = CellBep52PeerSessionV1::new([92; 32], reservation).unwrap();
    let result = fetch_cell_bep52_storage_v2(
        &destination,
        &f.binding,
        &[address],
        *b"-CV2001-read-peer001",
        &mut session,
    );
    worker.join().unwrap().unwrap();
    let report = result.unwrap();
    assert_eq!(report.payload_bytes, f.bytes.len() as u64);
    assert_eq!(report.downloaded_bytes, f.bytes.len() as u64);
    assert_eq!(report.downloaded_chunks, 2);
    assert_eq!(report.mapping_id, f.binding.mapping_id());
    assert_eq!(destination.cache_usage().unwrap().chunk_rows, 2);
    assert_eq!(session.usage().connection_attempts, 1);
    assert!(session.usage().received_bytes > f.bytes.len() as u64);
    destination.verify_complete(f.binding.manifest()).unwrap();

    let before = session.usage().clone();
    let resumed = fetch_cell_bep52_storage_v2(
        &destination,
        &f.binding,
        &[],
        *b"-CV2001-read-peer001",
        &mut session,
    )
    .unwrap();
    assert_eq!(resumed.cached_chunks, 2);
    assert_eq!(resumed.downloaded_bytes, 0);
    assert_eq!(
        session.usage().connection_attempts,
        before.connection_attempts
    );
    assert_eq!(session.usage().received_bytes, before.received_bytes);
    assert_eq!(session.usage().sent_bytes, before.sent_bytes);
    assert_eq!(
        session.usage().completed_fetches,
        before.completed_fetches + 1
    );
}

#[test]
fn partial_piece_failure_retains_wire_cost_and_resume_uses_same_session() {
    let f = fixture(65_537, 65_536);
    let reservation = limits();
    let mut short_service = reservation;
    short_service.max_sent_bytes = 20_000;
    let (first, failed_worker) = start_seed(&f.cache, &f.binding, short_service);
    let destination =
        CellStoreV1::open(&f.directory.path().join("receiver.sqlite"), config()).unwrap();
    let mut session = CellBep52PeerSessionV1::new([93; 32], reservation).unwrap();
    assert!(fetch_cell_bep52_storage_v2(
        &destination,
        &f.binding,
        &[first],
        *b"-CV2001-read-peer001",
        &mut session,
    )
    .is_err());
    assert!(failed_worker.join().unwrap().is_err());
    assert_eq!(destination.cache_usage().unwrap().chunk_rows, 0);
    assert_eq!(session.usage().connection_attempts, 1);
    assert_eq!(session.usage().refused_connections, 1);
    assert!(session.usage().received_bytes >= 16_384);
    let failed_bytes = session.usage().received_bytes;

    let (second, worker) = start_seed(&f.cache, &f.binding, reservation);
    let resumed = fetch_cell_bep52_storage_v2(
        &destination,
        &f.binding,
        &[first, second],
        *b"-CV2001-read-peer001",
        &mut session,
    );
    worker.join().unwrap().unwrap();
    let resumed = resumed.unwrap();
    assert_eq!(resumed.downloaded_bytes, f.bytes.len() as u64);
    assert_eq!(session.usage().connection_attempts, 2);
    assert_eq!(session.usage().refused_connections, 1);
    assert!(session.usage().received_bytes > failed_bytes + f.bytes.len() as u64);
    assert_eq!(session.refusals().len(), 1);
    destination.verify_complete(f.binding.manifest()).unwrap();
}

#[test]
fn cancellation_refuses_before_cache_or_socket_and_cannot_be_unlatched() {
    let f = fixture(65_537, 65_536);
    let destination =
        CellStoreV1::open(&f.directory.path().join("receiver.sqlite"), config()).unwrap();
    let mut session = CellBep52PeerSessionV1::new([94; 32], limits()).unwrap();
    let cancelled = session.cancellation_handle();
    cancelled.store(true, Ordering::Release);
    assert!(fetch_cell_bep52_storage_v2(
        &destination,
        &f.binding,
        &[],
        *b"-CV2001-read-peer001",
        &mut session,
    )
    .is_err());
    cancelled.store(false, Ordering::Release);
    assert!(fetch_cell_bep52_storage_v2(
        &destination,
        &f.binding,
        &[],
        *b"-CV2001-read-peer001",
        &mut session,
    )
    .is_err());
    assert_eq!(session.usage().connection_attempts, 0);
    assert_eq!(session.usage().received_bytes, 0);
    assert_eq!(destination.cache_usage().unwrap().chunk_rows, 0);
    assert_eq!(destination.cache_usage().unwrap().manifest_rows, 0);
}

#[test]
fn cached_original_chunks_do_not_substitute_for_complete_payload_digest() {
    let f = fixture(65_537, 65_536);
    let original = f.binding.manifest();
    let mut wrong = original.payload_sha256();
    wrong[0] ^= 1;
    let declared = CellManifestV1::new(
        original.context().clone(),
        original.size(),
        wrong,
        original.chunk_bytes(),
        original.chunks().to_vec(),
    )
    .unwrap();
    let declaration = CellBep52StorageBindingV2::from_roots(
        &declared,
        declared.id(),
        f.binding.piece_roots().to_vec(),
    );
    let imported = CellBep52StorageBindingV2::from_pinned_mapping(
        &declared,
        declared.id(),
        declared.context(),
        declaration.mapping_id(),
        &declaration.mapping_bytes(),
    )
    .unwrap();
    let store = CellStoreV1::open(&f.cache, config()).unwrap();
    let mut session = CellBep52PeerSessionV1::new([95; 32], limits()).unwrap();
    let result = fetch_cell_bep52_storage_v2(
        &store,
        &imported,
        &[],
        *b"-CV2001-read-peer001",
        &mut session,
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("complete payload digest"));
    assert_eq!(session.usage().completed_fetches, 0);
    assert_eq!(session.usage().connection_attempts, 0);
}

fn reference_node(bytes: &[u8], height: u32, index: usize) -> CellDigestV1 {
    if height == 0 {
        let start = index * 16_384;
        return if start >= bytes.len() {
            [0; 32]
        } else {
            Sha256::digest(&bytes[start..(start + 16_384).min(bytes.len())]).into()
        };
    }
    let left = reference_node(bytes, height - 1, 2 * index);
    let right = reference_node(bytes, height - 1, 2 * index + 1);
    Sha256::digest([left.as_slice(), right.as_slice()].concat()).into()
}

fn hash_request(root: CellDigestV1, base: u32, index: u32, length: u32, proofs: u32) -> Vec<u8> {
    let mut request = vec![21];
    request.extend_from_slice(&root);
    for number in [base, index, length, proofs] {
        request.extend_from_slice(&number.to_be_bytes());
    }
    request
}

#[test]
fn native_hash_messages_cover_leaf_piece_and_padding_layers_against_recursive_reference() {
    let f = fixture(65_537, 32_768);
    assert_eq!(f.binding.pieces_root(), reference_node(&f.bytes, 3, 0));
    let reservation = limits();
    let (address, worker) = start_seed(&f.cache, &f.binding, reservation);
    let mut stream = TcpStream::connect(address).unwrap();
    let mut session = CellBep52PeerSessionV1::new([96; 32], reservation).unwrap();
    session.connection().unwrap();
    let deadline = session.request_deadline().unwrap();
    session
        .write_all(
            &mut stream,
            &handshake(&f.binding, *b"-CV2001-read-peer001"),
            deadline,
        )
        .unwrap();
    receive_handshake(&mut stream, &f.binding, &mut session, deadline).unwrap();
    session
        .send_frame(&mut stream, &extension_handshake(None), deadline)
        .unwrap();
    let extension = session
        .read_frame(&mut stream, deadline, false)
        .unwrap()
        .unwrap();
    assert!(extension.starts_with(&[20, 0]));
    let bitfield = session
        .read_frame(&mut stream, deadline, false)
        .unwrap()
        .unwrap();
    assert_eq!(bitfield[0], 5);
    for (base, index, length, proofs) in [(0, 0, 2, 2), (1, 0, 2, 1), (0, 6, 2, 2)] {
        let request = hash_request(f.binding.pieces_root(), base, index, length, proofs);
        session.send_frame(&mut stream, &request, deadline).unwrap();
        let response = session
            .read_frame(&mut stream, deadline, false)
            .unwrap()
            .unwrap();
        let mut expected = request;
        expected[0] = 22;
        for offset in index..index + length {
            expected.extend_from_slice(&reference_node(&f.bytes, base, offset as usize));
        }
        for height in length.trailing_zeros()..=proofs {
            expected.extend_from_slice(&reference_node(
                &f.bytes,
                base + height,
                ((index >> height) ^ 1) as usize,
            ));
        }
        assert_eq!(response, expected);
    }
    let mut foreign = f.binding.pieces_root();
    foreign[0] ^= 1;
    for (root, base) in [(foreign, 0), (f.binding.pieces_root(), 2)] {
        let request = hash_request(root, base, 0, 2, 0);
        session.send_frame(&mut stream, &request, deadline).unwrap();
        let response = session
            .read_frame(&mut stream, deadline, false)
            .unwrap()
            .unwrap();
        let mut expected = request;
        expected[0] = 23;
        assert_eq!(response, expected);
    }
    stream.shutdown(Shutdown::Write).unwrap();
    worker.join().unwrap().unwrap();
}

#[test]
fn exhausted_connection_reservation_does_not_reset_for_storage_profile() {
    let f = fixture(65_537, 65_536);
    let destination =
        CellStoreV1::open(&f.directory.path().join("receiver.sqlite"), config()).unwrap();
    let mut reservation = limits();
    reservation.max_connections = 1;
    let mut session = CellBep52PeerSessionV1::new([97; 32], reservation).unwrap();
    session.connection().unwrap();
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = unused.local_addr().unwrap();
    let result = fetch_cell_bep52_storage_v2(
        &destination,
        &f.binding,
        &[address],
        *b"-CV2001-read-peer001",
        &mut session,
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("connection budget"));
    assert_eq!(session.usage().connection_attempts, 1);
    assert_eq!(session.usage().received_bytes, 0);
    assert_eq!(destination.cache_usage().unwrap().chunk_rows, 0);
}

#[test]
fn refusal_without_resolved_endpoint_is_still_charged() {
    let mut session = CellBep52PeerSessionV1::new([98; 32], limits()).unwrap();
    session.connection().unwrap();
    session.record_connection_refusal(None, &CellErrorV1::Unavailable);
    assert_eq!(session.usage().refused_connections, 1);
    assert!(session.refusals().is_empty());
}

#[test]
fn seed_detects_changed_source_before_caching_a_served_piece() {
    let f = fixture(65_537, 65_536);
    let store = CellStoreV1::open(&f.cache, config()).unwrap();
    let seed = CellBep52StorageSeedV2::prepare(
        &store,
        &f.binding,
        read_limits(&f.binding, limits().deadline),
    )
    .unwrap();
    let connection = rusqlite::Connection::open(&f.cache).unwrap();
    connection
        .execute(
            "DELETE FROM cell_chunks_v1 WHERE hash=?1",
            rusqlite::params![f.binding.manifest().chunks()[0].sha256.as_slice()],
        )
        .unwrap();
    let mut source = None;
    assert!(seed.load_chunk(0, &mut source, limits().deadline).is_err());
    assert!(source.is_none());
}
