use std::{
    fs,
    io::Cursor,
    net::TcpListener,
    path::PathBuf,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use super::*;
use crate::cell::{
    CellBep52BindingV1, CellCacheConfigV4, CellChunkV1, CellContextV1, CellManifestV1,
    CellReleaseLimitsV1, MAX_CHUNK_BYTES,
};

fn context() -> CellContextV1 {
    CellContextV1 {
        family: "bep52-storage-tcp-v2-test".into(),
        base: [1; 32],
        parent: [2; 32],
        tokenizer: [3; 32],
        layout: [4; 32],
        runtime: [5; 32],
    }
}

fn manifest(bytes: &[u8], chunk_bytes: u32) -> CellManifestV1 {
    CellManifestV1::new(
        context(),
        bytes.len() as u64,
        Sha256::digest(bytes).into(),
        chunk_bytes,
        bytes
            .chunks(chunk_bytes as usize)
            .map(|chunk| CellChunkV1 {
                size: chunk.len() as u32,
                sha256: Sha256::digest(chunk).into(),
            })
            .collect(),
    )
    .unwrap()
}

fn cache(path: &std::path::Path) -> CellStoreV1 {
    CellStoreV1::open(
        path,
        CellCacheConfigV4 {
            max_database_bytes: 16 * 1024 * 1024,
            max_logical_bytes: 12 * 1024 * 1024,
            max_chunk_rows: 512,
            max_manifest_rows: 8,
        },
    )
    .unwrap()
}

fn limits() -> CellBep52StoragePeerLimitsV2 {
    CellBep52StoragePeerLimitsV2 {
        deadline: Instant::now() + Duration::from_secs(30),
        request_timeout: Duration::from_secs(15),
        max_connections: 1,
        max_received_bytes: 16 * 1024 * 1024,
        max_sent_bytes: 16 * 1024 * 1024,
        max_messages: 2048,
    }
}

fn fixture(
    size: usize,
    chunk_bytes: u32,
) -> (
    tempfile::TempDir,
    PathBuf,
    Vec<u8>,
    CellBep52StorageBindingV2,
) {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.sqlite");
    let bytes: Vec<_> = (0..size)
        .map(|index| ((index * 131 + index / 16_384) % 251) as u8)
        .collect();
    let manifest = manifest(&bytes, chunk_bytes);
    let owner = CellBep52StorageBindingV2::from_pinned_reader(
        &manifest,
        manifest.id(),
        &context(),
        &mut Cursor::new(&bytes),
        CellReleaseLimitsV1 {
            max_payload_bytes: size as u64,
            max_chunks: manifest.chunks().len() as u64,
            deadline: Instant::now() + Duration::from_secs(30),
        },
    )
    .unwrap();
    let source = cache(&source_path);
    source
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    for (expected, actual) in manifest
        .chunks()
        .iter()
        .zip(bytes.chunks(chunk_bytes as usize))
    {
        source.put_chunk(expected, actual).unwrap();
    }
    drop(source);
    (directory, source_path, bytes, owner)
}

type ServerResult = (
    Result<CellBep52StorageServeReportV2, String>,
    CellBep52StoragePeerUsageV2,
);

fn spawn_seed(
    path: PathBuf,
    binding: CellBep52StorageBindingV2,
) -> (SocketAddr, thread::JoinHandle<ServerResult>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let reservation = limits();
    let job = thread::spawn(move || {
        let mut session = CellBep52StoragePeerSessionV2::new([9; 32], reservation).unwrap();
        let result = (|| {
            let source = CellStoreV1::open_read_only(&path)?;
            let stream = loop {
                session.check(session.deadline())?;
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            CellBep52StorageSeedV2::new(&source, &binding).serve_connection(stream, &mut session)
        })()
        .map_err(|error: CellErrorV1| error.to_string());
        (result, session.usage().clone())
    });
    (endpoint, job)
}

fn import_owner_pin(owner: &CellBep52StorageBindingV2) -> CellBep52StorageBindingV2 {
    CellBep52StorageBindingV2::from_pinned_mapping(
        owner.manifest(),
        owner.manifest_id(),
        &context(),
        owner.mapping_id(),
        &owner.mapping_bytes(),
    )
    .unwrap()
}

#[test]
fn actual_loopback_download_maps_257_transport_leaves_to_two_original_storage_chunks() {
    let (directory, source_path, bytes, owner) =
        fixture(MAX_CHUNK_BYTES as usize + 17, MAX_CHUNK_BYTES);
    // The old descriptor has the same file Merkle root but 257 storage records;
    // the new descriptor retains 16 KiB leaves over only two original chunks.
    let old_manifest = manifest(&bytes, 16_384);
    let old =
        CellBep52BindingV1::from_pinned_manifest(&old_manifest, old_manifest.id(), &context())
            .unwrap();
    assert_eq!(old.pieces_root(), owner.pieces_root());
    assert_eq!(old_manifest.chunks().len(), 257);
    assert_eq!(owner.manifest().chunks().len(), 2);
    let receiver = import_owner_pin(&owner);
    let target = cache(&directory.path().join("target.sqlite"));
    let (peer, job) = spawn_seed(source_path, owner);
    let reservation = limits();
    let mut session = CellBep52StoragePeerSessionV2::new([7; 32], reservation).unwrap();
    let report = fetch_cell_bep52_storage(&target, &receiver, &[peer], &mut session).unwrap();
    let (served, server_usage) = job.join().unwrap();
    let served = served.unwrap();
    assert_eq!(report.operation_id, [7; 32]);
    assert_eq!(report.downloaded_chunks, 2);
    assert_eq!(report.downloaded_leaves, 257);
    assert_eq!(report.downloaded_bytes, bytes.len() as u64);
    assert_eq!(served.chunk_requests, 2);
    assert_eq!(served.served_leaves, 257);
    assert_eq!(served.served_payload_bytes, bytes.len() as u64);
    assert_eq!(served.requester_operation_id, session.operation_id());
    assert_eq!(session.deadline(), reservation.deadline);
    assert_eq!(session.usage().connection_attempts, 1);
    assert_eq!(session.usage().completed_fetches, 1);
    assert_eq!(session.usage().received_bytes, server_usage.sent_bytes);
    assert_eq!(session.usage().sent_bytes, server_usage.received_bytes);
    assert!(session.usage().received_bytes > report.payload_bytes);
    target.verify_complete(receiver.manifest()).unwrap();
    let output = directory.path().join("download.bin");
    target.materialize(receiver.manifest(), &output).unwrap();
    assert_eq!(fs::read(output).unwrap(), bytes);
    let before = session.usage().clone();
    let cached = fetch_cell_bep52_storage(&target, &receiver, &[], &mut session).unwrap();
    assert_eq!(cached.downloaded_chunks, 0);
    assert_eq!(cached.downloaded_leaves, 0);
    assert_eq!(
        session.usage().connection_attempts,
        before.connection_attempts
    );
    assert_eq!(session.usage().received_bytes, before.received_bytes);
    assert_eq!(session.usage().sent_bytes, before.sent_bytes);
    assert_eq!(session.usage().completed_fetches, 2);
}

#[test]
fn partial_wire_budget_failure_does_not_publish_a_partial_storage_chunk_or_reset_attempts() {
    let (directory, source_path, _, owner) =
        fixture(MAX_CHUNK_BYTES as usize + 17, MAX_CHUNK_BYTES);
    let receiver = import_owner_pin(&owner);
    let target = cache(&directory.path().join("target.sqlite"));
    let (peer, job) = spawn_seed(source_path, owner);
    let mut reservation = limits();
    reservation.max_received_bytes = 32_000;
    let mut session = CellBep52StoragePeerSessionV2::new([7; 32], reservation).unwrap();
    assert!(fetch_cell_bep52_storage(&target, &receiver, &[peer], &mut session).is_err());
    let _ = job.join().unwrap();
    assert!(target
        .chunk(receiver.manifest().chunks()[0].sha256)
        .unwrap()
        .is_none());
    assert_eq!(session.usage().connection_attempts, 1);
    assert_eq!(session.usage().completed_fetches, 0);
    assert!(session.usage().received_bytes > 16_384);
    assert!(session.usage().received_bytes <= 32_000);
    let before = session.usage().clone();
    assert!(fetch_cell_bep52_storage(&target, &receiver, &[peer], &mut session).is_err());
    assert_eq!(session.operation_id(), [7; 32]);
    assert_eq!(session.deadline(), reservation.deadline);
    assert_eq!(
        session.usage().connection_attempts,
        before.connection_attempts
    );
    assert_eq!(session.usage().received_bytes, before.received_bytes);
    assert_eq!(session.usage().sent_bytes, before.sent_bytes);
}

#[test]
fn original_frame_budget_refuses_payload_after_the_two_frame_handshake() {
    let (directory, source_path, _, owner) = fixture(32_769, 32_768);
    let target = cache(&directory.path().join("target.sqlite"));
    let (peer, job) = spawn_seed(source_path, owner.clone());
    let mut reservation = limits();
    reservation.max_messages = 2;
    let mut session = CellBep52StoragePeerSessionV2::new([7; 32], reservation).unwrap();
    assert!(fetch_cell_bep52_storage(&target, &owner, &[peer], &mut session).is_err());
    let (served, _) = job.join().unwrap();
    assert_eq!(served.unwrap().served_leaves, 0);
    assert_eq!(
        session.usage().sent_messages + session.usage().received_messages,
        2
    );
    assert_eq!(session.usage().completed_fetches, 0);
    assert!(target
        .chunk(owner.manifest().chunks()[0].sha256)
        .unwrap()
        .is_none());
}

#[test]
fn a_different_peer_mapping_cannot_replace_the_original_owner_pin() {
    let (directory, source_path, _, owner) = fixture(32_769, 32_768);
    let (_, _, _, other) = fixture(32_770, 32_768);
    let target = cache(&directory.path().join("target.sqlite"));
    let (peer, job) = spawn_seed(source_path, owner);
    let mut session = CellBep52StoragePeerSessionV2::new([7; 32], limits()).unwrap();
    assert!(fetch_cell_bep52_storage(&target, &other, &[peer], &mut session).is_err());
    assert!(job.join().unwrap().0.is_err());
    assert_eq!(session.usage().completed_fetches, 0);
    assert!(target
        .chunk(other.manifest().chunks()[0].sha256)
        .unwrap()
        .is_none());
}

#[test]
fn inconsistent_owner_full_payload_digest_never_completes_a_fetch() {
    let (directory, source_path, _, owner) = fixture(32_769, 32_768);
    let declaration = CellManifestV1::new(
        context(),
        owner.manifest().size(),
        [231; 32],
        owner.manifest().chunk_bytes(),
        owner.manifest().chunks().to_vec(),
    )
    .unwrap();
    let mut wire = owner.mapping_bytes();
    wire[4..36].copy_from_slice(&declaration.id());
    let mut hash = Sha256::new();
    hash.update(b"trnm.cell-bep52-storage-mapping.v2\0");
    hash.update(&wire);
    let mapping_id = hash.finalize().into();
    let declared = CellBep52StorageBindingV2::from_pinned_mapping(
        &declaration,
        declaration.id(),
        &context(),
        mapping_id,
        &wire,
    )
    .unwrap();
    let target = cache(&directory.path().join("target.sqlite"));
    let (peer, job) = spawn_seed(source_path, declared.clone());
    let mut session = CellBep52StoragePeerSessionV2::new([7; 32], limits()).unwrap();
    assert!(fetch_cell_bep52_storage(&target, &declared, &[peer], &mut session).is_err());
    assert_eq!(job.join().unwrap().0.unwrap().served_leaves, 3);
    assert_eq!(session.usage().completed_fetches, 0);
    // Complete chunks remain valid cache objects, but are not a successful file.
    assert!(target
        .chunk(declaration.chunks()[0].sha256)
        .unwrap()
        .is_some());
    assert!(target.verify_complete(&declaration).is_err());
}

#[test]
fn scope_and_latched_cancellation_keep_the_original_session_owner() {
    let (directory, source_path, _, owner) = fixture(32_769, 32_768);
    let source = CellStoreV1::open_read_only(&source_path).unwrap();
    // Fetch writes only the pinned manifest, so a separate mutable target is
    // used even for the all-cache scenario.
    let target = cache(&directory.path().join("target.sqlite"));
    target
        .put_manifest(owner.manifest_id(), &owner.manifest().encode())
        .unwrap();
    for expected in owner.manifest().chunks() {
        let actual = source.chunk(expected.sha256).unwrap().unwrap();
        target.put_chunk(expected, &actual).unwrap();
    }
    let mut session = CellBep52StoragePeerSessionV2::new([7; 32], limits()).unwrap();
    fetch_cell_bep52_storage(&target, &owner, &[], &mut session).unwrap();
    let (_, _, _, other) = fixture(32_770, 32_768);
    assert!(fetch_cell_bep52_storage(&target, &other, &[], &mut session).is_err());
    assert!(target.manifest(other.manifest_id()).unwrap().is_none());
    let cancellation = session.cancellation_handle();
    cancellation.store(true, Ordering::Release);
    assert!(fetch_cell_bep52_storage(&target, &owner, &[], &mut session).is_err());
    cancellation.store(false, Ordering::Release);
    assert!(fetch_cell_bep52_storage(&target, &owner, &[], &mut session).is_err());
    assert_eq!(session.usage().completed_fetches, 1);
    assert_eq!(session.usage().connection_attempts, 0);
}

#[test]
fn stalled_peer_respects_the_original_request_deadline_without_cache_publication() {
    let (directory, _, _, owner) = fixture(32_769, 32_768);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let job = thread::spawn(move || {
        let accept_deadline = Instant::now() + Duration::from_secs(30);
        let stream = loop {
            assert!(Instant::now() < accept_deadline, "fixture accept deadline");
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("fixture accept: {error}"),
            }
        };
        // No response; finite fixture wait is independent of the client's timer.
        thread::sleep(Duration::from_millis(200));
        drop(stream);
    });
    let target = cache(&directory.path().join("target.sqlite"));
    let mut reservation = limits();
    reservation.request_timeout = Duration::from_millis(50);
    let mut session = CellBep52StoragePeerSessionV2::new([7; 32], reservation).unwrap();
    assert!(fetch_cell_bep52_storage(&target, &owner, &[endpoint], &mut session).is_err());
    job.join().unwrap();
    assert_eq!(session.deadline(), reservation.deadline);
    assert_eq!(session.usage().completed_fetches, 0);
    assert_eq!(session.usage().received_bytes, 0);
    assert!(target
        .chunk(owner.manifest().chunks()[0].sha256)
        .unwrap()
        .is_none());
}
