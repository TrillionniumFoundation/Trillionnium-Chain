//! Real byte-cache/transport controls. Local selection is neither CURRENT nor
//! FinalUse, and these payloads do not stand in for a model forward pass.

use std::{
    cell::Cell as Observed,
    collections::BTreeMap,
    fs, io,
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use crate::cell::*;

const CHUNK_BYTES: usize = 16_384;

type IndexMergeHook = Box<dyn FnOnce(Instant)>;

thread_local! {
    static INDEX_MERGE_HOOK: std::cell::RefCell<Option<IndexMergeHook>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn after_index_merge(deadline: Instant) {
    let hook = INDEX_MERGE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(deadline);
    }
}

fn with_index_merge_hook<T>(hook: IndexMergeHook, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            let _ = INDEX_MERGE_HOOK.with(|slot| slot.borrow_mut().take());
        }
    }
    INDEX_MERGE_HOOK.with(|slot| assert!(slot.borrow_mut().replace(hook).is_none()));
    let _reset = Reset;
    run()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(15)
}

fn expired() -> Instant {
    Instant::now() - Duration::from_secs(1)
}

fn cache_config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 8 * 1024 * 1024,
        max_logical_bytes: 4 * 1024 * 1024,
        max_chunk_rows: 128,
        max_manifest_rows: 128,
    }
}

fn resident_config() -> CellResidencyConfigV1 {
    CellResidencyConfigV1 {
        max_resident_bytes: 1024 * 1024,
        max_resident_closures: 8,
        max_chunk_references: 128,
    }
}

fn limits() -> CellReleaseFetchLimitsV1 {
    CellReleaseFetchLimitsV1 {
        peer: CellPeerLimitsV1 {
            request_timeout: Duration::from_secs(2),
            overall_timeout: Duration::from_secs(15),
            max_cell_bytes: 1024 * 1024,
            parallelism: 2,
            max_connections: 128,
            max_response_bytes: 4 * 1024 * 1024,
        },
        release: CellReleaseLimitsV1 {
            max_payload_bytes: 1024 * 1024,
            max_chunks: 128,
            deadline: deadline(),
        },
    }
}

fn expected(closure: &CellReleaseClosureV1) -> CellLoaderContextV1 {
    CellLoaderContextV1 {
        closure_id: closure.id(),
        context: closure.release().context().clone(),
        selected_generation: closure.selected_generation(),
        loader_profile: closure.loader_profile(),
        required_roles: vec![
            CellFileRoleV1::Adapter,
            CellFileRoleV1::Base,
            CellFileRoleV1::Tokenizer,
        ],
        max_payload_bytes: 1024 * 1024,
        max_chunks: 128,
    }
}

struct Fixture {
    closure: CellReleaseClosureV1,
    expected: CellLoaderContextV1,
    manifests: Vec<CellManifestV1>,
    payloads: Vec<Vec<u8>>,
}

impl Fixture {
    fn new(store: &CellStoreV1, adapter: u8, generation: u64) -> Self {
        // Three distinct base chunks exercise their order as well as physical
        // sharing. Each version changes its adapter and context's parent pin.
        let base = [
            vec![0x11; CHUNK_BYTES],
            vec![0x22; CHUNK_BYTES],
            vec![0x33; 37],
        ]
        .concat();
        let tokenizer = br#"{"vocab":{"token":0},"version":1}"#.to_vec();
        let context = CellContextV1 {
            family: "resident-bytes-controls-v1".into(),
            base: Sha256::digest(&base).into(),
            parent: [adapter; 32],
            tokenizer: Sha256::digest(&tokenizer).into(),
            layout: [0x41; 32],
            runtime: [0x42; 32],
        };
        let payloads = vec![vec![adapter; 4093], base, tokenizer];
        let manifests: Vec<_> = payloads
            .iter()
            .map(|bytes| {
                let chunks: Vec<_> = bytes
                    .chunks(CHUNK_BYTES)
                    .map(|chunk| CellChunkV1 {
                        size: chunk.len() as u32,
                        sha256: Sha256::digest(chunk).into(),
                    })
                    .collect();
                let manifest = CellManifestV1::new(
                    context.clone(),
                    bytes.len() as u64,
                    Sha256::digest(bytes).into(),
                    CHUNK_BYTES as u32,
                    chunks,
                )
                .unwrap();
                store
                    .put_manifest(manifest.id(), &manifest.encode())
                    .unwrap();
                for (expected, chunk) in manifest.chunks().iter().zip(bytes.chunks(CHUNK_BYTES)) {
                    store.put_chunk(expected, chunk).unwrap();
                }
                manifest
            })
            .collect();
        let files = [
            ("adapter.bin", CellFileRoleV1::Adapter),
            ("base.bin", CellFileRoleV1::Base),
            ("tokenizer.json", CellFileRoleV1::Tokenizer),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (path, role))| CellClosureFileV1 {
            path: path.into(),
            role,
            manifest: manifests[index].id(),
            payload_sha256: manifests[index].payload_sha256(),
            payload_bytes: manifests[index].size(),
            dependencies: if index == 0 { vec![1, 2] } else { vec![] },
        })
        .collect();
        let closure =
            CellReleaseClosureV1::new(context, generation, [0x77; 32], vec![0], files).unwrap();
        Self {
            expected: expected(&closure),
            closure,
            manifests,
            payloads,
        }
    }

    fn payload_bytes(&self) -> u64 {
        self.payloads.iter().map(|bytes| bytes.len() as u64).sum()
    }

    fn references(&self) -> usize {
        self.manifests
            .iter()
            .map(|manifest| manifest.chunks().len())
            .sum()
    }

    fn prepare(&self, manager: &mut CellResidencyV1, store: &CellStoreV1) {
        manager
            .prepare_cached(
                store,
                &self.closure,
                &self.expected,
                deadline(),
                &AtomicBool::new(false),
            )
            .unwrap();
    }

    fn assert_local(&self, manager: &CellResidencyV1) {
        let actual = manager
            .with_local(&self.expected, deadline(), |view| {
                assert_eq!(view.files().len(), self.closure.files().len());
                view.files()
                    .iter()
                    .zip(self.closure.files())
                    .map(|(resident, declared)| {
                        assert_eq!(resident.path(), declared.path);
                        assert_eq!(resident.role(), declared.role);
                        assert_eq!(resident.manifest_id(), declared.manifest);
                        assert_eq!(resident.payload_sha256(), declared.payload_sha256);
                        let bytes: Vec<_> = resident
                            .chunks()
                            .flat_map(|chunk| chunk.iter().copied())
                            .collect();
                        assert_eq!(
                            <CellDigestV1>::from(Sha256::digest(&bytes)),
                            declared.payload_sha256
                        );
                        bytes
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap();
        assert_eq!(actual, self.payloads);
    }
}

fn usage(manager: &CellResidencyV1) -> (u64, usize, usize, usize) {
    let usage = manager.usage();
    (
        usage.unique_payload_bytes,
        usage.unique_chunks,
        usage.resident_closures,
        usage.chunk_references,
    )
}

struct Peer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<CellResultV1<u64>>>,
}

impl Peer {
    fn start(path: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let path = path.to_owned();
        let handle = thread::spawn(move || {
            let store = CellStoreV1::open_read_only(&path)?;
            serve_cells(&listener, &store, &shutdown, limits().peer)
        });
        Self {
            address,
            stop,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap().unwrap()
    }

    /// A fixed-response TCP peer, with one finite deadline for every accept,
    /// read and write. Cancellation is requested only after a complete actual
    /// chunk response has been written; the transport does not observe this
    /// external flag until the caller's complete-fetch phase has returned.
    fn cancel_after_first_chunk(fixture: &Fixture, cancelled: Arc<AtomicBool>) -> Self {
        let mut replies = BTreeMap::new();
        for (manifest, payload) in fixture.manifests.iter().zip(&fixture.payloads) {
            replies.insert((1_u8, manifest.id()), manifest.encode());
            for (chunk, bytes) in manifest.chunks().iter().zip(payload.chunks(CHUNK_BYTES)) {
                replies.insert((2_u8, chunk.sha256), bytes.to_vec());
            }
        }
        let expected_requests = fixture.manifests.len() + fixture.references();
        assert_eq!(
            replies.len(),
            expected_requests,
            "fixture uses distinct chunks"
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let handle = thread::spawn(move || {
            let cutoff = Instant::now() + Duration::from_secs(5);
            let mut chunk_responses = 0;
            for _ in 0..expected_requests {
                let mut stream = loop {
                    if shutdown.load(Ordering::Acquire) {
                        return Err(CellErrorV1::Invalid("fixed response peer stopped"));
                    }
                    crate::cell::network::remaining(cutoff)?;
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                let mut query = [0; 37];
                crate::cell::network::read_deadline(&mut stream, &mut query, cutoff, None)?;
                assert_eq!(&query[..4], b"TCQ1");
                let digest: CellDigestV1 = query[5..].try_into().unwrap();
                let bytes = replies
                    .remove(&(query[4], digest))
                    .ok_or(CellErrorV1::Invalid("unexpected fixed response request"))?;
                let mut header = [0; 9];
                header[..4].copy_from_slice(b"TCS1");
                header[5..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
                crate::cell::network::write_deadline(&mut stream, &header, cutoff)?;
                crate::cell::network::write_deadline(&mut stream, &bytes, cutoff)?;
                if query[4] == 2 {
                    chunk_responses += 1;
                    if chunk_responses == 1 {
                        cancelled.store(true, Ordering::Release);
                    }
                }
            }
            Ok(chunk_responses)
        });
        Self {
            address,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn residency_tcp_prefetch_then_100_local_reads_need_neither_provider_nor_disk_cache() {
    let directory = tempfile::tempdir().unwrap();
    let caches = directory.path().join("caches");
    fs::create_dir(&caches).unwrap();
    let origin_path = caches.join("origin.sqlite");
    let origin = CellStoreV1::open(&origin_path, cache_config()).unwrap();
    let fixture = Fixture::new(&origin, 0x71, 7);
    let consumer = CellStoreV1::open(&caches.join("consumer.sqlite"), cache_config()).unwrap();
    let mut manager = CellResidencyV1::new(resident_config()).unwrap();
    let provider = Peer::start(&origin_path);
    let address = provider.address;
    let report = manager
        .prefetch(
            &consumer,
            &fixture.closure,
            &fixture.expected,
            &[address],
            limits(),
            &AtomicBool::new(false),
        )
        .unwrap()
        .fetch
        .unwrap();
    assert_eq!(report.closure_id, fixture.closure.id());
    assert_eq!(report.release.downloaded_bytes, fixture.payload_bytes());
    assert_eq!(report.release.downloaded_chunks, fixture.references());
    assert!(report.release.connection_attempts > 0);
    assert!(provider.finish() > 0);
    assert_eq!(
        manager.selection(),
        None,
        "prefetch must not select a release"
    );
    // The same pinned request is already resident, even with a dead provider.
    assert!(manager
        .prefetch(
            &consumer,
            &fixture.closure,
            &fixture.expected,
            &[address],
            limits(),
            &AtomicBool::new(false),
        )
        .unwrap()
        .fetch
        .is_none());
    manager.pin_hot(&fixture.expected).unwrap();
    let selected = manager
        .select_local(None, &fixture.expected, deadline(), &AtomicBool::new(false))
        .unwrap();
    assert_eq!(selected.closure_id(), fixture.closure.id());
    drop(origin);
    drop(consumer);
    fs::remove_dir_all(&caches).unwrap();
    for _ in 0..100 {
        fixture.assert_local(&manager);
        assert_eq!(
            manager
                .with_selected(&fixture.expected, deadline(), |view| view.files().len())
                .unwrap(),
            3
        );
    }
    assert_eq!(usage(&manager).0, fixture.payload_bytes());
}

#[test]
fn residency_two_versions_share_the_same_base_buffers_but_keep_distinct_file_mappings() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x71, 7);
    let b = Fixture::new(&store, 0x72, 8);
    assert_ne!(a.manifests[1].id(), b.manifests[1].id());
    assert_eq!(a.manifests[1].chunks(), b.manifests[1].chunks());
    let mut manager = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut manager, &store);
    b.prepare(&mut manager, &store);
    a.assert_local(&manager);
    b.assert_local(&manager);
    let addresses = |expected: &CellLoaderContextV1| {
        manager
            .with_local(expected, deadline(), |view| {
                view.files()
                    .iter()
                    .find(|file| file.role() == CellFileRoleV1::Base)
                    .unwrap()
                    .chunks()
                    .map(|chunk| (chunk.as_ptr() as usize, chunk.len()))
                    .collect::<Vec<_>>()
            })
            .unwrap()
    };
    assert_eq!(addresses(&a.expected), addresses(&b.expected));
    assert_eq!(
        usage(&manager),
        (
            a.payload_bytes() + b.payloads[0].len() as u64,
            a.references() + 1,
            2,
            a.references() + b.references(),
        )
    );
}

#[test]
fn residency_hits_recheck_exact_version_generation_profile_roles_and_loader_budgets() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let fixture = Fixture::new(&store, 0x71, 7);
    let mut manager = CellResidencyV1::new(resident_config()).unwrap();
    fixture.prepare(&mut manager, &store);
    let mut variants = vec![];
    let mut wrong = fixture.expected.clone();
    wrong.closure_id[0] ^= 1;
    variants.push(wrong);
    let mut wrong = fixture.expected.clone();
    wrong.selected_generation += 1;
    variants.push(wrong);
    let mut wrong = fixture.expected.clone();
    wrong.loader_profile[0] ^= 1;
    variants.push(wrong);
    let mut wrong = fixture.expected.clone();
    wrong.context.parent[0] ^= 1;
    variants.push(wrong);
    let mut wrong = fixture.expected.clone();
    wrong.required_roles = vec![CellFileRoleV1::Adapter, CellFileRoleV1::Adapter];
    variants.push(wrong);
    let mut wrong = fixture.expected.clone();
    wrong.max_payload_bytes = fixture.payload_bytes() - 1;
    variants.push(wrong);
    let mut wrong = fixture.expected.clone();
    wrong.max_chunks = fixture.references() as u64 - 1;
    variants.push(wrong);
    let original_usage = usage(&manager);
    for wrong in variants {
        let called = Observed::new(false);
        assert!(manager
            .with_local(&wrong, deadline(), |_| called.set(true))
            .is_err());
        assert!(
            !called.get(),
            "an invalid owner pin reached the byte consumer"
        );
        assert!(manager.pin_hot(&wrong).is_err());
        assert!(manager
            .select_local(None, &wrong, deadline(), &AtomicBool::new(false))
            .is_err());
        assert_eq!(manager.selection(), None);
        assert_eq!(usage(&manager), original_usage);
    }
    fixture.assert_local(&manager);
}

#[test]
fn residency_local_selection_compare_and_swap_rejects_stale_and_aba_tickets() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x71, 7);
    let b = Fixture::new(&store, 0x72, 8);
    let mut manager = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut manager, &store);
    b.prepare(&mut manager, &store);
    let running = AtomicBool::new(false);
    let first = manager
        .select_local(None, &a.expected, deadline(), &running)
        .unwrap();
    let mut foreign = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut foreign, &store);
    let foreign_ticket = foreign
        .select_local(None, &a.expected, deadline(), &running)
        .unwrap();
    assert_eq!(first.closure_id(), foreign_ticket.closure_id());
    assert_eq!(first.revision(), foreign_ticket.revision());
    assert_ne!(first, foreign_ticket, "CAS tickets belong to one manager");
    assert!(manager
        .select_local(Some(foreign_ticket), &b.expected, deadline(), &running)
        .is_err());
    assert!(manager
        .select_local(None, &b.expected, deadline(), &running)
        .is_err());
    let second = manager
        .select_local(Some(first), &b.expected, deadline(), &running)
        .unwrap();
    assert!(manager
        .with_selected(&a.expected, deadline(), |_| ())
        .is_err());
    let third = manager
        .select_local(Some(second), &a.expected, deadline(), &running)
        .unwrap();
    assert_eq!(first.closure_id(), third.closure_id());
    assert_ne!(
        first, third,
        "returning to A must not recreate an old CAS ticket"
    );
    assert!(manager
        .select_local(Some(first), &b.expected, deadline(), &running)
        .is_err());
    assert_eq!(manager.selection(), Some(third));
    a.assert_local(&manager);
}

#[test]
fn residency_byte_quota_refuses_new_release_without_evicting_hot_or_selected_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x71, 7);
    let b = Fixture::new(&store, 0x72, 8);
    let mut manager = CellResidencyV1::new(CellResidencyConfigV1 {
        max_resident_bytes: a.payload_bytes(),
        ..resident_config()
    })
    .unwrap();
    a.prepare(&mut manager, &store);
    manager.pin_hot(&a.expected).unwrap();
    assert!(manager.evict(a.closure.id()).is_err());
    let selected = manager
        .select_local(None, &a.expected, deadline(), &AtomicBool::new(false))
        .unwrap();
    let before = usage(&manager);
    assert!(manager
        .prepare_cached(
            &store,
            &b.closure,
            &b.expected,
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
    assert_eq!(usage(&manager), before);
    assert_eq!(manager.selection(), Some(selected));
    manager.unpin_hot(a.closure.id()).unwrap();
    assert!(
        manager.evict(a.closure.id()).is_err(),
        "selection still holds the bytes"
    );
    a.assert_local(&manager);
    assert!(manager.with_local(&b.expected, deadline(), |_| ()).is_err());
}

#[test]
fn residency_known_closure_capacity_refuses_prefetch_before_any_peer_connection() {
    let directory = tempfile::tempdir().unwrap();
    let origin =
        CellStoreV1::open(&directory.path().join("origin.sqlite"), cache_config()).unwrap();
    let consumer =
        CellStoreV1::open(&directory.path().join("consumer.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&origin, 0x71, 7);
    let b = Fixture::new(&origin, 0x72, 8);
    let mut manager = CellResidencyV1::new(CellResidencyConfigV1 {
        max_resident_closures: 1,
        ..resident_config()
    })
    .unwrap();
    a.prepare(&mut manager, &origin);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let before = usage(&manager);
    assert!(manager
        .prefetch(
            &consumer,
            &b.closure,
            &b.expected,
            &[listener.local_addr().unwrap()],
            limits(),
            &AtomicBool::new(false),
        )
        .is_err());
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    assert_eq!(usage(&manager), before);
    assert_eq!(consumer.cache_usage().unwrap().chunk_rows, 0);
    assert_eq!(consumer.cache_usage().unwrap().manifest_rows, 0);
}

#[test]
fn residency_expired_or_cancelled_preparation_and_switch_preserve_the_old_selection() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x71, 7);
    let b = Fixture::new(&store, 0x72, 8);
    let mut manager = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut manager, &store);
    let running = AtomicBool::new(false);
    let cancelled = AtomicBool::new(true);
    let selected = manager
        .select_local(None, &a.expected, deadline(), &running)
        .unwrap();
    let before = usage(&manager);
    for (cutoff, cancel) in [(expired(), &running), (deadline(), &cancelled)] {
        assert!(manager
            .prepare_cached(&store, &b.closure, &b.expected, cutoff, cancel)
            .is_err());
        assert_eq!(usage(&manager), before);
        assert_eq!(manager.selection(), Some(selected));
    }
    b.prepare(&mut manager, &store);
    for (cutoff, cancel) in [(expired(), &running), (deadline(), &cancelled)] {
        assert!(manager
            .select_local(Some(selected), &b.expected, cutoff, cancel)
            .is_err());
        assert_eq!(manager.selection(), Some(selected));
    }
    let called = Observed::new(false);
    assert!(manager
        .with_selected(&a.expected, expired(), |_| called.set(true))
        .is_err());
    assert!(!called.get());
    a.assert_local(&manager);
    b.assert_local(&manager);
}

#[test]
fn residency_incomplete_prefetch_retains_old_selection_and_retry_only_prepares_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.sqlite");
    let store = CellStoreV1::open(&path, cache_config()).unwrap();
    let a = Fixture::new(&store, 0x71, 7);
    let b = Fixture::new(&store, 0x72, 8);
    let mut manager = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut manager, &store);
    let selected = manager
        .select_local(None, &a.expected, deadline(), &AtomicBool::new(false))
        .unwrap();
    let missing = &b.manifests[0].chunks()[0];
    Connection::open(&path)
        .unwrap()
        .execute(
            "DELETE FROM cell_chunks_v1 WHERE hash=?1",
            [missing.sha256.as_slice()],
        )
        .unwrap();
    let before = usage(&manager);
    assert!(manager
        .prefetch(
            &store,
            &b.closure,
            &b.expected,
            &[],
            limits(),
            &AtomicBool::new(false),
        )
        .is_err());
    assert_eq!(manager.selection(), Some(selected));
    assert_eq!(usage(&manager), before);
    assert!(manager.with_local(&b.expected, deadline(), |_| ()).is_err());
    a.assert_local(&manager);
    store.put_chunk(missing, &b.payloads[0]).unwrap();
    let report = manager
        .prefetch(
            &store,
            &b.closure,
            &b.expected,
            &[],
            limits(),
            &AtomicBool::new(false),
        )
        .unwrap();
    if let Some(fetch) = report.fetch {
        assert_eq!(fetch.release.connection_attempts, 0);
        assert_eq!(fetch.release.downloaded_bytes, 0);
    }
    assert_eq!(manager.selection(), Some(selected));
    b.assert_local(&manager);
}

#[test]
fn residency_corrupt_cache_cannot_create_a_new_view_or_mutate_existing_immutable_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.sqlite");
    let store = CellStoreV1::open(&path, cache_config()).unwrap();
    let a = Fixture::new(&store, 0x71, 7);
    let b = Fixture::new(&store, 0x72, 8);
    let mut manager = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut manager, &store);
    let before = usage(&manager);
    let external = Connection::open(&path).unwrap();
    for fixture in [&a, &b] {
        let chunk = &fixture.manifests[0].chunks()[0];
        assert_eq!(
            external
                .execute(
                    "UPDATE cell_chunks_v1 SET bytes=?1 WHERE hash=?2",
                    params![vec![0_u8; chunk.size as usize], chunk.sha256.as_slice()],
                )
                .unwrap(),
            1
        );
    }
    drop(external);
    assert!(manager
        .prepare_cached(
            &store,
            &b.closure,
            &b.expected,
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
    assert_eq!(usage(&manager), before);
    assert!(manager.with_local(&b.expected, deadline(), |_| ()).is_err());
    // A was copied and verified before the cache corruption. Its borrowed
    // buffers must not alias SQLite, an external mutable file, or a reread.
    a.assert_local(&manager);
}

#[test]
fn residency_valid_individual_chunks_do_not_bypass_the_ordered_payload_digest() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let good = Fixture::new(&store, 0x71, 7);
    let wrong = CellManifestV1::new(
        good.expected.context.clone(),
        good.manifests[1].size(),
        [0xef; 32],
        CHUNK_BYTES as u32,
        good.manifests[1].chunks().to_vec(),
    )
    .unwrap();
    store.put_manifest(wrong.id(), &wrong.encode()).unwrap();
    let mut files = good.closure.files().to_vec();
    files[1].manifest = wrong.id();
    files[1].payload_sha256 = wrong.payload_sha256();
    let bad = CellReleaseClosureV1::new(
        good.expected.context.clone(),
        8,
        good.expected.loader_profile,
        vec![0],
        files,
    )
    .unwrap();
    let mut manager = CellResidencyV1::new(resident_config()).unwrap();
    good.prepare(&mut manager, &store);
    let before = usage(&manager);
    // Every required chunk is already resident under its correct hash. Reuse
    // must still validate this new manifest's complete ordered payload hash.
    assert!(manager
        .prepare_cached(
            &store,
            &bad,
            &expected(&bad),
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
    assert_eq!(usage(&manager), before);
    good.assert_local(&manager);
}

#[test]
fn residency_restart_reuses_fixed_disk_bytes_but_restores_no_local_selection_or_hot_pin() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cache.sqlite");
    let store = CellStoreV1::open(&path, cache_config()).unwrap();
    let fixture = Fixture::new(&store, 0x71, 7);
    let mut old = CellResidencyV1::new(resident_config()).unwrap();
    fixture.prepare(&mut old, &store);
    old.pin_hot(&fixture.expected).unwrap();
    old.select_local(None, &fixture.expected, deadline(), &AtomicBool::new(false))
        .unwrap();
    drop(old);
    drop(store);
    let reopened = CellStoreV1::open(&path, cache_config()).unwrap();
    let mut restored = CellResidencyV1::new(resident_config()).unwrap();
    assert_eq!(usage(&restored), (0, 0, 0, 0));
    assert_eq!(restored.selection(), None);
    assert!(restored
        .with_local(&fixture.expected, deadline(), |_| ())
        .is_err());
    fixture.prepare(&mut restored, &reopened);
    fixture.assert_local(&restored);
    assert_eq!(restored.selection(), None);
    assert!(restored
        .with_selected(&fixture.expected, deadline(), |_| ())
        .is_err());
    restored.evict(fixture.closure.id()).unwrap();
    assert_eq!(usage(&restored), (0, 0, 0, 0));
}

#[test]
fn residency_reference_budget_counts_shared_mappings_and_eviction_releases_all_unpinned_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x71, 7);
    let b = Fixture::new(&store, 0x72, 8);
    let mut manager = CellResidencyV1::new(CellResidencyConfigV1 {
        max_chunk_references: a.references(),
        ..resident_config()
    })
    .unwrap();
    a.prepare(&mut manager, &store);
    let before = usage(&manager);
    assert!(manager
        .prepare_cached(
            &store,
            &b.closure,
            &b.expected,
            deadline(),
            &AtomicBool::new(false),
        )
        .is_err());
    assert_eq!(usage(&manager), before);
    a.assert_local(&manager);
    manager.evict(a.closure.id()).unwrap();
    assert_eq!(usage(&manager), (0, 0, 0, 0));
    b.prepare(&mut manager, &store);
    assert_eq!(
        usage(&manager),
        (b.payload_bytes(), b.references(), 1, b.references())
    );
    b.assert_local(&manager);
}

#[test]
fn residency_cancellation_after_index_merge_rolls_back_only_new_chunks_and_retry_recharges() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x71, 7);
    let b = Fixture::new(&store, 0x72, 8);
    let mut manager = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut manager, &store);
    manager.pin_hot(&a.expected).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let selected = manager
        .select_local(None, &a.expected, deadline(), &cancelled)
        .unwrap();
    let before_usage = usage(&manager);
    let before_keys: Vec<_> = manager.chunks.keys().copied().collect();
    let reached = Arc::new(AtomicBool::new(false));
    let observed = reached.clone();
    let cancel_at_merge = cancelled.clone();
    let original = deadline();
    let result = with_index_merge_hook(
        Box::new(move |cutoff| {
            assert_eq!(
                cutoff, original,
                "index merge renewed the original deadline"
            );
            observed.store(true, Ordering::Release);
            cancel_at_merge.store(true, Ordering::Release);
        }),
        || manager.prepare_cached(&store, &b.closure, &b.expected, original, &cancelled),
    );
    assert!(
        reached.load(Ordering::Acquire),
        "index merge hook was not reached"
    );
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("resident operation cancelled"))
    ));
    assert_eq!(
        manager.chunks.keys().copied().collect::<Vec<_>>(),
        before_keys
    );
    assert_eq!(usage(&manager), before_usage);
    assert_eq!(manager.selection(), Some(selected));
    assert!(manager.with_local(&b.expected, deadline(), |_| ()).is_err());
    a.assert_local(&manager);
    cancelled.store(false, Ordering::Release);
    manager
        .prepare_cached(&store, &b.closure, &b.expected, deadline(), &cancelled)
        .unwrap();
    assert_eq!(
        usage(&manager),
        (
            a.payload_bytes() + b.payloads[0].len() as u64,
            a.references() + 1,
            2,
            a.references() + b.references(),
        )
    );
    assert_eq!(manager.selection(), Some(selected));
    a.assert_local(&manager);
    b.assert_local(&manager);
    manager.evict(b.closure.id()).unwrap();
    assert_eq!(usage(&manager), before_usage);
    assert_eq!(
        manager.chunks.keys().copied().collect::<Vec<_>>(),
        before_keys
    );
}

#[test]
fn residency_deadline_after_index_merge_rolls_back_new_chunks_without_renewal() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x71, 7);
    let b = Fixture::new(&store, 0x72, 8);
    let mut manager = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut manager, &store);
    manager.pin_hot(&a.expected).unwrap();
    let running = AtomicBool::new(false);
    let selected = manager
        .select_local(None, &a.expected, deadline(), &running)
        .unwrap();
    let before_usage = usage(&manager);
    let before_keys: Vec<_> = manager.chunks.keys().copied().collect();
    let reached = Arc::new(AtomicBool::new(false));
    let observed = reached.clone();
    let window = Duration::from_millis(100);
    let original = Instant::now() + window;
    let result = with_index_merge_hook(
        Box::new(move |cutoff| {
            assert_eq!(
                cutoff, original,
                "index merge renewed the original deadline"
            );
            observed.store(true, Ordering::Release);
            while Instant::now() < original {
                let remaining = original.saturating_duration_since(Instant::now());
                assert!(remaining <= window);
                thread::sleep(remaining);
            }
        }),
        || manager.prepare_cached(&store, &b.closure, &b.expected, original, &running),
    );
    assert!(
        reached.load(Ordering::Acquire),
        "index merge hook was not reached"
    );
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("resident operation deadline"))
    ));
    assert_eq!(
        manager.chunks.keys().copied().collect::<Vec<_>>(),
        before_keys
    );
    assert_eq!(usage(&manager), before_usage);
    assert_eq!(manager.selection(), Some(selected));
    assert!(manager.with_local(&b.expected, deadline(), |_| ()).is_err());
    a.assert_local(&manager);
    b.prepare(&mut manager, &store);
    assert_eq!(
        usage(&manager),
        (
            a.payload_bytes() + b.payloads[0].len() as u64,
            a.references() + 1,
            2,
            a.references() + b.references(),
        )
    );
    assert_eq!(manager.selection(), Some(selected));
    b.assert_local(&manager);
    manager.evict(b.closure.id()).unwrap();
    assert_eq!(usage(&manager), before_usage);
    assert_eq!(
        manager.chunks.keys().copied().collect::<Vec<_>>(),
        before_keys
    );
}

#[test]
fn residency_tcp_mid_download_cancellation_is_observed_after_bounded_complete_fetch() {
    let directory = tempfile::tempdir().unwrap();
    let origin =
        CellStoreV1::open(&directory.path().join("origin.sqlite"), cache_config()).unwrap();
    let consumer =
        CellStoreV1::open(&directory.path().join("consumer.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&origin, 0x71, 7);
    let b = Fixture::new(&origin, 0x72, 8);
    let mut manager = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut manager, &origin);
    manager.pin_hot(&a.expected).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let selected = manager
        .select_local(None, &a.expected, deadline(), &cancelled)
        .unwrap();
    let before_usage = usage(&manager);
    let before_keys: Vec<_> = manager.chunks.keys().copied().collect();
    let provider = Peer::cancel_after_first_chunk(&b, cancelled.clone());
    let mut bounded = limits();
    bounded.peer.parallelism = 1;
    let result = manager.prefetch(
        &consumer,
        &b.closure,
        &b.expected,
        &[provider.address],
        bounded,
        &cancelled,
    );
    // This is deliberately a phase-boundary cancellation contract: subsequent
    // bounded socket work completes after the first chunk triggers cancellation.
    // It must not be described as immediate interruption of an in-flight fetch.
    let chunk_responses = provider.finish();
    assert_eq!(chunk_responses, b.references() as u64);
    assert!(chunk_responses > 1);
    assert!(cancelled.load(Ordering::Acquire));
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("resident operation cancelled"))
    ));
    assert_eq!(
        manager.chunks.keys().copied().collect::<Vec<_>>(),
        before_keys
    );
    assert_eq!(usage(&manager), before_usage);
    assert_eq!(manager.selection(), Some(selected));
    assert!(manager.with_local(&b.expected, deadline(), |_| ()).is_err());
    a.assert_local(&manager);
    consumer
        .verify_release_complete(b.closure.release(), limits().release)
        .unwrap();
    cancelled.store(false, Ordering::Release);
    let retry = manager
        .prefetch(
            &consumer,
            &b.closure,
            &b.expected,
            &[],
            limits(),
            &cancelled,
        )
        .unwrap()
        .fetch
        .expect("a new resident closure retains its acquisition report");
    assert_eq!(retry.release.connection_attempts, 0);
    assert_eq!(retry.release.downloaded_bytes, 0);
    assert_eq!(retry.release.cached_chunks, b.references());
    assert_eq!(manager.selection(), Some(selected));
    assert_eq!(
        usage(&manager),
        (
            a.payload_bytes() + b.payloads[0].len() as u64,
            a.references() + 1,
            2,
            a.references() + b.references(),
        )
    );
    a.assert_local(&manager);
    b.assert_local(&manager);
}
