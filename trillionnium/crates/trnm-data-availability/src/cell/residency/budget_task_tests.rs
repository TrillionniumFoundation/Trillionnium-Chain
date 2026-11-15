//! Native byte-cache controls. These fixtures are neither model inference nor
//! NVMe hardware, GPU/device residency or CURRENT/FinalUse acceptance evidence.

use std::{
    cell::Cell,
    fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use crate::cell::*;

const CHUNK: usize = 16_384;
const ADAPTER: usize = 61;
const TASK: CellDigestV1 = [0xa1; 32];

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

fn cache_config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 4 * 1024 * 1024,
        max_logical_bytes: 1024 * 1024,
        max_chunk_rows: 64,
        max_manifest_rows: 64,
    }
}

fn resident_config() -> CellResidencyConfigV1 {
    CellResidencyConfigV1 {
        max_resident_bytes: 256 * 1024,
        max_resident_closures: 8,
        max_chunk_references: 64,
    }
}

fn fetch_limits() -> CellReleaseFetchLimitsV1 {
    CellReleaseFetchLimitsV1 {
        peer: CellPeerLimitsV1 {
            request_timeout: Duration::from_secs(2),
            overall_timeout: Duration::from_secs(20),
            max_cell_bytes: 256 * 1024,
            parallelism: 2,
            max_connections: 32,
            max_response_bytes: 512 * 1024,
        },
        release: CellReleaseLimitsV1 {
            max_payload_bytes: 256 * 1024,
            max_chunks: 64,
            deadline: deadline(),
        },
    }
}

struct Fixture {
    closure: CellReleaseClosureV1,
    expected: CellLoaderContextV1,
    manifests: Vec<CellManifestV1>,
    payloads: Vec<Vec<u8>>,
}

impl Fixture {
    fn new(store: &CellStoreV1, variant: u8, generation: u64) -> Self {
        // The base's two positions share one physical chunk. Different releases
        // have different adapters/contexts but reuse that same resident buffer.
        let payloads = vec![vec![variant; ADAPTER], vec![0x31; CHUNK * 2]];
        let context = CellContextV1 {
            family: "resident-task-controls-v1".into(),
            base: Sha256::digest(&payloads[1]).into(),
            parent: [variant; 32],
            tokenizer: [0x22; 32],
            layout: [0x23; 32],
            runtime: [0x24; 32],
        };
        let manifests: Vec<_> = payloads
            .iter()
            .map(|payload| {
                let chunks = payload
                    .chunks(CHUNK)
                    .map(|bytes| CellChunkV1 {
                        sha256: Sha256::digest(bytes).into(),
                        size: bytes.len() as u32,
                    })
                    .collect();
                let manifest = CellManifestV1::new(
                    context.clone(),
                    payload.len() as u64,
                    Sha256::digest(payload).into(),
                    CHUNK as u32,
                    chunks,
                )
                .unwrap();
                store
                    .put_manifest(manifest.id(), &manifest.encode())
                    .unwrap();
                for (chunk, bytes) in manifest.chunks().iter().zip(payload.chunks(CHUNK)) {
                    store.put_chunk(chunk, bytes).unwrap();
                }
                manifest
            })
            .collect();
        let files = [
            ("adapter.bin", CellFileRoleV1::Adapter, vec![1]),
            ("base.bin", CellFileRoleV1::Base, vec![]),
        ]
        .into_iter()
        .zip(&manifests)
        .map(|((path, role, dependencies), manifest)| CellClosureFileV1 {
            path: path.into(),
            role,
            manifest: manifest.id(),
            payload_sha256: manifest.payload_sha256(),
            payload_bytes: manifest.size(),
            dependencies,
        })
        .collect();
        let closure =
            CellReleaseClosureV1::new(context.clone(), generation, [0x41; 32], vec![0], files)
                .unwrap();
        let expected = CellLoaderContextV1 {
            closure_id: closure.id(),
            context,
            selected_generation: generation,
            loader_profile: closure.loader_profile(),
            required_roles: vec![CellFileRoleV1::Adapter, CellFileRoleV1::Base],
            max_payload_bytes: 256 * 1024,
            max_chunks: 64,
        };
        Self {
            closure,
            expected,
            manifests,
            payloads,
        }
    }

    fn prepare(&self, pool: &mut CellResidencyV1, store: &CellStoreV1) {
        pool.prepare_cached(
            store,
            &self.closure,
            &self.expected,
            deadline(),
            &AtomicBool::new(false),
        )
        .unwrap();
    }

    fn metadata_response_bytes(&self) -> u64 {
        self.manifests
            .iter()
            .map(|manifest| manifest.encode().len() as u64 + 9)
            .sum()
    }

    fn complete_response_bytes(&self) -> u64 {
        self.metadata_response_bytes() + (CHUNK + ADAPTER + 18) as u64
    }
}

struct RecordingPeer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<Vec<u8>>>,
}

impl RecordingPeer {
    fn start(cache: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&shutdown);
        let path = cache.to_owned();
        let worker = thread::spawn(move || {
            let store = CellStoreV1::open_read_only(&path).unwrap();
            let cutoff = deadline();
            let mut kinds = Vec::new();
            while !stopped.load(Ordering::Acquire) && Instant::now() < cutoff {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("recording provider accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut query = [0; 37];
                stream.read_exact(&mut query).unwrap();
                assert_eq!(&query[..4], b"TCQ1");
                kinds.push(query[4]);
                let digest = query[5..].try_into().unwrap();
                let payload = match query[4] {
                    1 => store.manifest(digest).unwrap().unwrap().encode(),
                    2 => store.chunk(digest).unwrap().unwrap(),
                    kind => panic!("unexpected recording provider request {kind}"),
                };
                let mut reply = b"TCS1\0".to_vec();
                reply.extend((payload.len() as u32).to_be_bytes());
                reply.extend(payload);
                // A receiver exhausting its original allowance may close after
                // a partial response; the request remains a recorded attempt.
                let _ = stream.write_all(&reply);
            }
            kinds
        });
        Self {
            address,
            shutdown,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> Vec<u8> {
        self.shutdown.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap()
    }
}

impl Drop for RecordingPeer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn capacity_refusal_before_payload(config: CellResidencyConfigV1, expected_reason: &str) {
    let directory = tempfile::tempdir().unwrap();
    let origin_path = directory.path().join("origin.sqlite");
    let origin = CellStoreV1::open(&origin_path, cache_config()).unwrap();
    let consumer =
        CellStoreV1::open(&directory.path().join("consumer.sqlite"), cache_config()).unwrap();
    let old = Fixture::new(&origin, 0x51, 7);
    let next = Fixture::new(&origin, 0x52, 8);
    let mut pool = CellResidencyV1::new(config).unwrap();
    old.prepare(&mut pool, &origin);
    let cancelled = AtomicBool::new(false);
    let selected = pool
        .select_local(None, &old.expected, deadline(), &cancelled)
        .unwrap();
    let before = pool.usage();
    let peer = RecordingPeer::start(&origin_path);
    let error = pool
        .prefetch(
            &consumer,
            &next.closure,
            &next.expected,
            &[peer.address],
            fetch_limits(),
            &cancelled,
        )
        .unwrap_err();
    let kinds = peer.finish();
    assert!(matches!(error, CellErrorV1::Invalid(reason) if reason == expected_reason));
    assert_eq!(kinds, vec![1; next.manifests.len()]);
    assert_eq!(consumer.cache_usage().unwrap().chunk_rows, 0);
    assert_eq!(consumer.cache_usage().unwrap().manifest_rows, 2);
    assert_eq!(pool.usage(), before);
    assert_eq!(pool.selection(), Some(selected));
    pool.with_selected(&old.expected, deadline(), |_| ())
        .unwrap();
}

#[test]
fn prefetch_ram_capacity_refuses_after_metadata_before_any_payload_request() {
    capacity_refusal_before_payload(
        CellResidencyConfigV1 {
            max_resident_bytes: (CHUNK + ADAPTER) as u64,
            ..resident_config()
        },
        "resident byte budget",
    );
}

#[test]
fn prefetch_reference_capacity_refuses_after_metadata_before_any_payload_request() {
    capacity_refusal_before_payload(
        CellResidencyConfigV1 {
            max_chunk_references: 3,
            ..resident_config()
        },
        "resident reference budget",
    );
}

#[test]
fn prefetch_deduplicates_exact_ram_needs_and_preserves_complete_transport_counts() {
    let directory = tempfile::tempdir().unwrap();
    let origin_path = directory.path().join("origin.sqlite");
    let origin = CellStoreV1::open(&origin_path, cache_config()).unwrap();
    let consumer =
        CellStoreV1::open(&directory.path().join("consumer.sqlite"), cache_config()).unwrap();
    let fixture = Fixture::new(&origin, 0x51, 7);
    let mut pool = CellResidencyV1::new(CellResidencyConfigV1 {
        max_resident_bytes: (CHUNK + ADAPTER) as u64,
        max_chunk_references: 3,
        ..resident_config()
    })
    .unwrap();
    let mut limits = fetch_limits();
    limits.peer.max_connections = 4;
    limits.peer.max_response_bytes = fixture.complete_response_bytes();
    let peer = RecordingPeer::start(&origin_path);
    let report = pool
        .prefetch(
            &consumer,
            &fixture.closure,
            &fixture.expected,
            &[peer.address],
            limits,
            &AtomicBool::new(false),
        )
        .unwrap()
        .fetch
        .unwrap();
    assert_eq!(peer.finish(), [1, 1, 2, 2]);
    assert_eq!(report.release.connection_attempts, 4);
    assert_eq!(
        report.release.received_response_bytes,
        fixture.complete_response_bytes()
    );
    assert_eq!(report.release.downloaded_chunks, 3);
    assert_eq!(report.release.downloaded_bytes, (CHUNK + ADAPTER) as u64);
    assert_eq!(pool.usage().unique_chunks, 2);
    assert_eq!(pool.usage().unique_payload_bytes, (CHUNK + ADAPTER) as u64);
    assert_eq!(pool.usage().chunk_references, 3);
}

#[test]
fn prefetch_readiness_does_not_refresh_connection_or_response_allowances() {
    for only_metadata in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let origin_path = directory.path().join("origin.sqlite");
        let origin = CellStoreV1::open(&origin_path, cache_config()).unwrap();
        let consumer =
            CellStoreV1::open(&directory.path().join("consumer.sqlite"), cache_config()).unwrap();
        let fixture = Fixture::new(&origin, 0x51, 7);
        let mut pool = CellResidencyV1::new(resident_config()).unwrap();
        let mut limits = fetch_limits();
        if only_metadata {
            limits.peer.max_response_bytes = fixture.metadata_response_bytes();
        } else {
            limits.peer.max_connections = 3;
        }
        let peer = RecordingPeer::start(&origin_path);
        assert!(pool
            .prefetch(
                &consumer,
                &fixture.closure,
                &fixture.expected,
                &[peer.address],
                limits,
                &AtomicBool::new(false),
            )
            .is_err());
        let expected = if only_metadata {
            vec![1, 1]
        } else {
            vec![1, 1, 2]
        };
        assert_eq!(peer.finish(), expected);
        assert_eq!(pool.usage(), CellResidencyUsageV1::default());
        assert_eq!(pool.selection(), None);
        assert_eq!(
            consumer.cache_usage().unwrap().chunk_rows,
            u64::from(!only_metadata)
        );
    }
}

fn canonical(fixtures: &[&Fixture]) -> Vec<CellLoaderContextV1> {
    let mut expected: Vec<_> = fixtures
        .iter()
        .map(|fixture| fixture.expected.clone())
        .collect();
    expected.sort_by_key(|context| context.closure_id);
    expected
}

#[test]
fn task_working_set_is_complete_deduplicated_and_runs_with_no_disk_or_peer() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x51, 7);
    let b = Fixture::new(&store, 0x52, 8);
    let mut pool = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut pool, &store);
    b.prepare(&mut pool, &store);
    let expected = canonical(&[&a, &b]);
    let cancelled = AtomicBool::new(false);
    let before = pool.usage();
    let set = pool
        .admit_local_working_set(
            TASK,
            &expected,
            CellResidencyConfigV1 {
                max_resident_bytes: (CHUNK + ADAPTER * 2) as u64,
                max_resident_closures: 2,
                max_chunk_references: 6,
            },
            deadline(),
            &cancelled,
        )
        .unwrap();
    assert_eq!(set.task_id(), TASK);
    assert_eq!(set.usage(), before);
    assert_eq!(set.usage().unique_chunks, 3);
    assert_eq!(
        set.usage().unique_payload_bytes,
        (CHUNK + ADAPTER * 2) as u64
    );
    assert_eq!(set.usage().chunk_references, 6);
    drop(store);
    fs::remove_dir_all(directory.path()).unwrap();
    for fixture in [&a, &b] {
        let actual = set
            .with_local(TASK, &fixture.expected, |view| {
                view.files()
                    .iter()
                    .map(|file| file.chunks().flatten().copied().collect::<Vec<_>>())
                    .collect::<Vec<_>>()
            })
            .unwrap();
        assert_eq!(actual, fixture.payloads);
    }
    drop(set);
    pool.evict(b.expected.closure_id).unwrap();
    assert_eq!(pool.usage().resident_closures, 1);
}

#[test]
fn task_working_set_refuses_missing_or_noncanonical_members_without_partial_readiness() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x51, 7);
    let b = Fixture::new(&store, 0x52, 8);
    let missing = Fixture::new(&store, 0x53, 9);
    let mut pool = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut pool, &store);
    b.prepare(&mut pool, &store);
    let cancelled = AtomicBool::new(false);
    let selected = pool
        .select_local(None, &a.expected, deadline(), &cancelled)
        .unwrap();
    let before = pool.usage();
    let mut reversed = canonical(&[&a, &b]);
    reversed.reverse();
    for expected in [
        vec![],
        vec![a.expected.clone(), a.expected.clone()],
        reversed,
        canonical(&[&a, &b, &missing]),
    ] {
        assert!(pool
            .admit_local_working_set(TASK, &expected, resident_config(), deadline(), &cancelled,)
            .is_err());
        assert_eq!(pool.usage(), before);
        assert_eq!(pool.selection(), Some(selected));
    }
}

#[test]
fn task_working_set_enforces_all_aggregate_limits_and_nonzero_task_identity() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x51, 7);
    let b = Fixture::new(&store, 0x52, 8);
    let mut pool = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut pool, &store);
    b.prepare(&mut pool, &store);
    let expected = canonical(&[&a, &b]);
    let cancelled = AtomicBool::new(false);
    let before = pool.usage();
    for limits in [
        CellResidencyConfigV1 {
            max_resident_bytes: before.unique_payload_bytes - 1,
            ..resident_config()
        },
        CellResidencyConfigV1 {
            max_resident_closures: 1,
            ..resident_config()
        },
        CellResidencyConfigV1 {
            max_chunk_references: before.chunk_references - 1,
            ..resident_config()
        },
        CellResidencyConfigV1 {
            max_resident_bytes: 0,
            ..resident_config()
        },
    ] {
        assert!(pool
            .admit_local_working_set(TASK, &expected, limits, deadline(), &cancelled)
            .is_err());
        assert_eq!(pool.usage(), before);
    }
    assert!(pool
        .admit_local_working_set(
            [0; 32],
            &expected,
            resident_config(),
            deadline(),
            &cancelled,
        )
        .is_err());
}

#[test]
fn task_lookup_rechecks_current_context_and_never_invokes_consumer_after_a_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x51, 7);
    let mut pool = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut pool, &store);
    let cancelled = AtomicBool::new(false);
    let set = pool
        .admit_local_working_set(
            TASK,
            std::slice::from_ref(&a.expected),
            resident_config(),
            deadline(),
            &cancelled,
        )
        .unwrap();
    let calls = Cell::new(0);
    assert!(set
        .with_local([0x99; 32], &a.expected, |_| calls.set(calls.get() + 1))
        .is_err());
    for mode in 0..7 {
        let mut current = a.expected.clone();
        match mode {
            0 => current.selected_generation += 1,
            1 => current.loader_profile = [0x81; 32],
            2 => current.context.runtime = [0x82; 32],
            3 => current.closure_id = [0x83; 32],
            4 => current.required_roles = vec![CellFileRoleV1::Router],
            5 => current.max_payload_bytes = 1,
            6 => current.max_chunks = 1,
            _ => unreachable!(),
        }
        assert!(set
            .with_local(TASK, &current, |_| calls.set(calls.get() + 1))
            .is_err());
    }
    assert_eq!(calls.get(), 0);
    set.with_local(TASK, &a.expected, |_| calls.set(calls.get() + 1))
        .unwrap();
    assert_eq!(calls.get(), 1);
}

#[test]
fn task_cancellation_is_latched_and_does_not_promise_erasure_of_copied_public_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x51, 7);
    let mut pool = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut pool, &store);
    let cancelled = AtomicBool::new(false);
    let set = pool
        .admit_local_working_set(
            TASK,
            std::slice::from_ref(&a.expected),
            resident_config(),
            deadline(),
            &cancelled,
        )
        .unwrap();
    let copied = set
        .with_local(TASK, &a.expected, |view| {
            view.files()[0]
                .chunks()
                .flatten()
                .copied()
                .collect::<Vec<_>>()
        })
        .unwrap();
    let before = pool.usage();
    cancelled.store(true, Ordering::Release);
    assert!(set.with_local(TASK, &a.expected, |_| ()).is_err());
    cancelled.store(false, Ordering::Release);
    assert!(matches!(
        set.with_local(TASK, &a.expected, |_| ()),
        Err(CellErrorV1::Invalid("resident task stopped"))
    ));
    assert_eq!(copied, a.payloads[0]);
    assert_eq!(pool.usage(), before);
}

#[test]
fn task_cutoff_cannot_be_renewed_by_a_later_hot_lookup() {
    let directory = tempfile::tempdir().unwrap();
    let store = CellStoreV1::open(&directory.path().join("cache.sqlite"), cache_config()).unwrap();
    let a = Fixture::new(&store, 0x51, 7);
    let mut pool = CellResidencyV1::new(resident_config()).unwrap();
    a.prepare(&mut pool, &store);
    let cancelled = AtomicBool::new(false);
    let cutoff = Instant::now() + Duration::from_millis(100);
    let set = pool
        .admit_local_working_set(
            TASK,
            std::slice::from_ref(&a.expected),
            resident_config(),
            cutoff,
            &cancelled,
        )
        .unwrap();
    thread::sleep(cutoff.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
    assert!(matches!(
        set.with_local(TASK, &a.expected, |_| ()),
        Err(CellErrorV1::Invalid("resident operation deadline"))
    ));
    assert!(matches!(
        set.with_local(TASK, &a.expected, |_| ()),
        Err(CellErrorV1::Invalid("resident task stopped"))
    ));
    assert!(pool
        .admit_local_working_set(
            TASK,
            std::slice::from_ref(&a.expected),
            resident_config(),
            cutoff,
            &cancelled,
        )
        .is_err());
}
