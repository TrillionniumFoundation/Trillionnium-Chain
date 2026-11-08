use super::*;
use crate::cell::{
    serve_cells_persistent_with_ready,
    version::tests::{fixture, owner},
    CellCacheConfigV4, CellChunkV1, CellClosureFileV1, CellFetchTransportV2, CellFileRoleV1,
    CellLoaderContextV1, CellModelReleaseRootV1, CellPeerLimitsV1, CellPersistentServeLimitsV2,
    CellPersistentServeReportV2, CellReleaseClosureV1, CellReleaseFetchLimitsV1,
    CellReleaseLimitsV1, CellServeLimitsV1,
};
use sha2::Sha256;
use std::{
    collections::BTreeSet,
    io,
    net::TcpListener,
    path::Path,
    sync::{atomic::Ordering, mpsc, Arc},
    thread::{self, JoinHandle},
    time::Duration,
};

const PAYLOAD_BYTES: u64 = 32_769;
const CHUNK_BYTES: usize = 16_384;

fn recompose(original: &CellVersionManifestV1, generation: u64) -> CellVersionManifestV1 {
    let before = original.model().closure();
    let mut files = before.files().to_vec();
    // The same bytes have a different graph: tokenizer is an explicit root,
    // instead of a dependency of base. Neither graph may replace the other.
    files[0].dependencies.clear();
    let closure = CellReleaseClosureV1::new(
        before.release().context().clone(),
        generation,
        before.loader_profile(),
        vec![0, 1],
        files,
    )
    .unwrap();
    CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(closure, vec![]).unwrap(),
        original.environment().clone(),
        original.manifests().to_vec(),
    )
    .unwrap()
}

fn with_adapter(
    original: &CellVersionManifestV1,
) -> (CellVersionManifestV1, CellManifestV1, Vec<u8>) {
    let before = original.model().closure();
    let existing_chunks: BTreeSet<_> = original
        .manifests()
        .iter()
        .flat_map(|manifest| manifest.chunks().iter().map(|chunk| chunk.sha256))
        .collect();
    let (manifest, bytes) = (1u8..=u8::MAX)
        .find_map(|seed| {
            let bytes: Vec<_> = (0..PAYLOAD_BYTES as usize + 1)
                .map(|index| seed.wrapping_add((index % 251) as u8))
                .collect();
            let chunks = bytes
                .chunks(CHUNK_BYTES)
                .map(|part| CellChunkV1 {
                    size: part.len() as u32,
                    sha256: Sha256::digest(part).into(),
                })
                .collect();
            let manifest = CellManifestV1::new(
                before.release().context().clone(),
                bytes.len() as u64,
                Sha256::digest(&bytes).into(),
                CHUNK_BYTES as u32,
                chunks,
            )
            .unwrap();
            // An earlier admissible object must not hide a later oversized or
            // unavailable one. Fixture construction performs no cache writes.
            (manifest.id() > original.manifests()[0].id()
                && manifest
                    .chunks()
                    .iter()
                    .all(|chunk| !existing_chunks.contains(&chunk.sha256)))
            .then_some((manifest, bytes))
        })
        .unwrap();
    let mut files = vec![CellClosureFileV1 {
        path: "adapter-v2.bin".into(),
        role: CellFileRoleV1::Adapter,
        manifest: manifest.id(),
        payload_sha256: manifest.payload_sha256(),
        payload_bytes: manifest.size(),
        dependencies: vec![1],
    }];
    files.extend(before.files().iter().cloned().map(|mut file| {
        for dependency in &mut file.dependencies {
            *dependency += 1;
        }
        file
    }));
    let closure = CellReleaseClosureV1::new(
        before.release().context().clone(),
        before.selected_generation() + 1,
        before.loader_profile(),
        vec![0],
        files,
    )
    .unwrap();
    let mut manifests = original.manifests().to_vec();
    manifests.push(manifest.clone());
    manifests.sort_by_key(CellManifestV1::id);
    let version = CellVersionManifestV1::new(
        CellModelReleaseRootV1::new(closure, vec![original.model().id()]).unwrap(),
        original.environment().clone(),
        manifests,
    )
    .unwrap();
    (version, manifest, bytes)
}

fn install(store: &CellStoreV1, manifest: &CellManifestV1, bytes: &[u8]) {
    store
        .put_manifest(manifest.id(), &manifest.encode())
        .unwrap();
    for (chunk, bytes) in manifest.chunks().iter().zip(bytes.chunks(CHUNK_BYTES)) {
        store.put_chunk(chunk, bytes).unwrap();
    }
}

fn retained(versions: Vec<CellVersionManifestV1>) -> CellRetainedVersionSetV1 {
    let mut entries: Vec<_> = versions
        .into_iter()
        .map(|version| CellRetainedVersionEntryV1 {
            version,
            retain_from_height: 20,
            retain_until_height: 100,
        })
        .collect();
    entries.sort_by_key(|entry| entry.version.commitment());
    CellRetainedVersionSetV1::new(7, entries).unwrap()
}

fn loader_pins(set: &CellRetainedVersionSetV1) -> Vec<(CellLoaderContextV1, CellLoaderContextV1)> {
    set.entries()
        .iter()
        .map(|entry| {
            (
                owner(entry.version.model().closure(), CellFileRoleV1::Base),
                owner(entry.version.environment(), CellFileRoleV1::Configuration),
            )
        })
        .collect()
}

fn version_views<'a>(
    set: &CellRetainedVersionSetV1,
    pins: &'a [(CellLoaderContextV1, CellLoaderContextV1)],
) -> Vec<CellVersionLoaderContextV1<'a>> {
    set.entries()
        .iter()
        .zip(pins)
        .map(|(entry, (model, environment))| CellVersionLoaderContextV1 {
            commitment: entry.version.commitment(),
            model,
            environment,
        })
        .collect()
}

fn retained_owner<'a>(
    set: &CellRetainedVersionSetV1,
    versions: &'a [CellVersionLoaderContextV1<'a>],
) -> CellRetainedSetOwnerV1<'a> {
    CellRetainedSetOwnerV1 {
        commitment: set.commitment(),
        epoch: set.epoch(),
        current_height: 30,
        required_until_height: 90,
        versions,
    }
}

fn read_budget() -> CellRetainedReadBudgetV1 {
    CellRetainedReadBudgetV1::new(
        Instant::now() + Duration::from_secs(10),
        4,
        64,
        4_000_000,
        256,
    )
}

fn read_limits() -> CellReleaseLimitsV1 {
    CellReleaseLimitsV1 {
        max_payload_bytes: 1_000_000,
        max_chunks: 64,
        deadline: Instant::now() + Duration::from_secs(10),
    }
}

fn verify_version(store: &CellStoreV1, version: &CellVersionManifestV1) {
    let model = owner(version.model().closure(), CellFileRoleV1::Base);
    let environment = owner(version.environment(), CellFileRoleV1::Configuration);
    version
        .verify_cached(
            store,
            &CellVersionLoaderContextV1 {
                commitment: version.commitment(),
                model: &model,
                environment: &environment,
            },
            read_limits(),
        )
        .unwrap();
}

fn empty_store(path: &Path) -> CellStoreV1 {
    CellStoreV1::open(
        path,
        CellCacheConfigV4 {
            max_database_bytes: 64 << 20,
            max_logical_bytes: 32 << 20,
            max_chunk_rows: 128,
            max_manifest_rows: 64,
        },
    )
    .unwrap()
}

fn cache_rows(path: &Path) -> (u64, u64) {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT (SELECT count(*) FROM cell_manifests_v1),
                (SELECT count(*) FROM cell_chunks_v1)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn network_options(requests: u64, response_bytes: u64) -> CellReleaseFetchOptionsV2 {
    CellReleaseFetchOptionsV2 {
        limits: CellReleaseFetchLimitsV1 {
            peer: CellPeerLimitsV1 {
                request_timeout: Duration::from_secs(2),
                overall_timeout: Duration::from_secs(10),
                max_cell_bytes: 1_000_000,
                parallelism: 1,
                max_connections: 1,
                max_response_bytes: response_bytes,
            },
            release: read_limits(),
        },
        transport: CellFetchTransportV2::PersistentV2 {
            max_requests: requests,
            max_requests_per_connection: requests,
        },
    }
}

fn assert_no_preflight_effects(
    set: &CellRetainedVersionSetV1,
    expected: &CellRetainedSetOwnerV1<'_>,
    options: CellReleaseFetchOptionsV2,
    cancelled: Option<&AtomicBool>,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.sqlite");
    let store = empty_store(&path);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let failure = fetch_retained_version_set(
        &store,
        set,
        expected,
        &[listener.local_addr().unwrap()],
        options,
        cancelled,
    )
    .unwrap_err();
    assert_eq!(
        failure.usage,
        CellRetainedFetchUsageV1 {
            received_response_bytes: Some(0),
            ..CellRetainedFetchUsageV1::default()
        }
    );
    assert_eq!(cache_rows(&path), (0, 0));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

// The new version contains every old object plus one adapter, so its wire cost
// is an independent expected union cost for these native transport tests.
fn wire_cost(version: &CellVersionManifestV1) -> (u64, u64) {
    let chunk_ids: BTreeSet<_> = version
        .manifests()
        .iter()
        .flat_map(|manifest| manifest.chunks().iter().map(|chunk| chunk.sha256))
        .collect();
    let chunk_count: usize = version
        .manifests()
        .iter()
        .map(|manifest| manifest.chunks().len())
        .sum();
    assert_eq!(chunk_ids.len(), chunk_count);
    version
        .manifests()
        .iter()
        .fold((0, 0), |(frames, bytes), manifest| {
            let requests = 1 + manifest.chunks().len() as u64;
            (
                frames + requests,
                bytes + manifest.encode().len() as u64 + manifest.size() + 9 * requests,
            )
        })
}

struct Server {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<CellResultV1<CellPersistentServeReportV2>>>,
}

impl Server {
    fn start(path: &Path, requests: u64, response_bytes: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        let path = path.to_owned();
        let (send_ready, ready) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            serve_cells_persistent_with_ready(
                &listener,
                &path,
                &stop,
                CellPersistentServeLimitsV2 {
                    serving: CellServeLimitsV1 {
                        request_timeout: Duration::from_secs(2),
                        overall_timeout: Duration::from_secs(10),
                        max_workers: 1,
                        max_connections: 1,
                        max_response_bytes: response_bytes,
                    },
                    max_requests: requests,
                    max_requests_per_connection: requests,
                },
                &|| {
                    send_ready
                        .send(())
                        .map_err(|_| CellErrorV1::Invalid("test readiness receiver"))
                },
            )
        });
        let server = Self {
            address,
            shutdown,
            worker: Some(worker),
        };
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        server
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

#[test]
fn retained_set_refuses_empty_duplicate_unordered_and_invalid_original_terms() {
    let (_dir, _store, original) = fixture();
    let set = retained(vec![original.clone(), recompose(&original, 3)]);
    assert!(CellRetainedVersionSetV1::new(7, vec![]).is_err());
    assert!(CellRetainedVersionSetV1::new(0, set.entries().to_vec()).is_err());
    assert!(CellRetainedVersionSetV1::new(
        7,
        vec![set.entries()[0].clone(), set.entries()[0].clone()]
    )
    .is_err());
    let mut reverse = set.entries().to_vec();
    reverse.reverse();
    assert!(CellRetainedVersionSetV1::new(7, reverse).is_err());
    for (start, end) in [(100, 100), (101, 100), (20, i64::MAX as u64 + 1)] {
        let mut entries = set.entries().to_vec();
        entries[0].retain_from_height = start;
        entries[0].retain_until_height = end;
        assert!(CellRetainedVersionSetV1::new(7, entries).is_err());
    }
    let mut too_many: Vec<_> = (0..=MAX_CELL_RETAINED_VERSIONS_V1)
        .map(|index| CellRetainedVersionEntryV1 {
            version: recompose(&original, index as u64 + 3),
            retain_from_height: 20,
            retain_until_height: 100,
        })
        .collect();
    too_many.sort_by_key(|entry| entry.version.commitment());
    assert!(CellRetainedVersionSetV1::new(7, too_many).is_err());
}

#[test]
fn retained_commitment_binds_epoch_and_each_original_interval() {
    let (_dir, _store, original) = fixture();
    let set = retained(vec![original.clone(), recompose(&original, 3)]);
    let changed_epoch = CellRetainedVersionSetV1::new(8, set.entries().to_vec()).unwrap();
    assert_ne!(set.commitment(), changed_epoch.commitment());
    for index in 0..set.entries().len() {
        for change_start in [false, true] {
            let mut entries = set.entries().to_vec();
            if change_start {
                entries[index].retain_from_height += 1;
            } else {
                entries[index].retain_until_height += 1;
            }
            let changed = CellRetainedVersionSetV1::new(set.epoch(), entries).unwrap();
            assert_ne!(set.commitment(), changed.commitment());
        }
    }
}

#[test]
fn owner_must_pin_exact_roster_epoch_and_current_exclusive_horizon() {
    let (_dir, _store, original) = fixture();
    let set = retained(vec![original.clone(), recompose(&original, 3)]);
    let pins = loader_pins(&set);
    let views = version_views(&set, &pins);
    set.verify_for_owner(&retained_owner(&set, &views)).unwrap();

    let mut expected = retained_owner(&set, &views);
    expected.epoch += 1;
    assert!(set.verify_for_owner(&expected).is_err());
    expected = retained_owner(&set, &views);
    expected.commitment[0] ^= 1;
    assert!(set.verify_for_owner(&expected).is_err());
    assert!(set
        .verify_for_owner(&retained_owner(&set, &views[..1]))
        .is_err());
    let subset = retained(vec![set.entries()[0].version.clone()]);
    assert!(subset
        .verify_for_owner(&retained_owner(&set, &views[..1]))
        .is_err());

    let mut reordered = version_views(&set, &pins);
    reordered.reverse();
    assert!(set
        .verify_for_owner(&retained_owner(&set, &reordered))
        .is_err());
    let mut duplicated = version_views(&set, &pins);
    duplicated[1].commitment = duplicated[0].commitment;
    assert!(set
        .verify_for_owner(&retained_owner(&set, &duplicated))
        .is_err());

    for (current, until) in [(19, 90), (100, 101), (30, 101), (30, 30), (31, 30)] {
        let mut expected = retained_owner(&set, &views);
        expected.current_height = current;
        expected.required_until_height = until;
        assert!(set.verify_for_owner(&expected).is_err());
    }
    for current in [20, 99] {
        let mut expected = retained_owner(&set, &views);
        expected.current_height = current;
        expected.required_until_height = 100;
        set.verify_for_owner(&expected).unwrap();
    }
}

#[test]
fn last_version_loader_identity_is_checked_before_read_admission() {
    let (_dir, store, original) = fixture();
    let set = retained(vec![original.clone(), recompose(&original, 3)]);
    let pins = loader_pins(&set);
    for mismatch in 0..5 {
        let mut changed = pins.clone();
        let (model, environment) = changed.last_mut().unwrap();
        match mismatch {
            0 => model.context.tokenizer[0] ^= 1,
            1 => model.context.runtime[0] ^= 1,
            2 => environment.context.runtime[0] ^= 1,
            3 => model.selected_generation += 1,
            4 => environment.loader_profile[0] ^= 1,
            _ => unreachable!(),
        }
        let views = version_views(&set, &changed);
        let mut budget = read_budget();
        assert!(set
            .verify_cached(&store, &retained_owner(&set, &views), &mut budget)
            .is_err());
        assert_eq!(budget.usage(), CellRetainedReadUsageV1::default());
    }
}

#[test]
fn distinct_compositions_keep_their_pins_while_shared_objects_are_read_once() {
    let (_dir, store, original) = fixture();
    let alternate = recompose(&original, 3);
    assert_ne!(original.model().id(), alternate.model().id());
    assert_ne!(
        original.model().closure().roots(),
        alternate.model().closure().roots()
    );
    assert_eq!(original.manifests(), alternate.manifests());
    verify_version(&store, &original);
    verify_version(&store, &alternate);

    let set = retained(vec![original, alternate]);
    let pins = loader_pins(&set);
    let views = version_views(&set, &pins);
    let expected = retained_owner(&set, &views);
    let objects = set.referenced_objects().unwrap();
    let versions: Vec<_> = set
        .entries()
        .iter()
        .map(|entry| entry.version.commitment())
        .collect();
    assert_eq!(objects.len(), 4);
    for object in &objects {
        assert_eq!(object.versions, versions);
        assert_eq!((object.payload_bytes, object.chunks), (PAYLOAD_BYTES, 3));
    }
    let mut budget = CellRetainedReadBudgetV1::new(
        Instant::now() + Duration::from_secs(10),
        1,
        4,
        4 * PAYLOAD_BYTES,
        12,
    );
    let report = set.verify_cached(&store, &expected, &mut budget).unwrap();
    assert_eq!(report.commitment(), set.commitment());
    assert_eq!((report.epoch(), report.current_height()), (7, 30));
    assert_eq!(report.versions(), versions.as_slice());
    assert_eq!(
        (report.manifests(), report.payload_bytes(), report.chunks()),
        (4, 4 * PAYLOAD_BYTES, 12)
    );
    assert_eq!(
        budget.usage(),
        CellRetainedReadUsageV1 {
            attempts_committed: 1,
            manifests_committed: 4,
            payload_bytes_committed: 4 * PAYLOAD_BYTES,
            chunks_committed: 12,
        }
    );
    let (started, finished) = report.observation_window();
    assert!(started <= finished && finished <= Instant::now());

    let substituted = [
        CellVersionLoaderContextV1 {
            commitment: views[0].commitment,
            model: views[0].model,
            environment: views[0].environment,
        },
        CellVersionLoaderContextV1 {
            commitment: views[1].commitment,
            model: views[0].model,
            environment: views[1].environment,
        },
    ];
    assert!(set
        .verify_for_owner(&retained_owner(&set, &substituted))
        .is_err());
}

#[test]
fn unique_new_version_dependency_cannot_be_hidden_by_complete_old_version() {
    let (dir, store, original) = fixture();
    let (next, adapter, bytes) = with_adapter(&original);
    install(&store, &adapter, &bytes);
    let set = retained(vec![original.clone(), next.clone()]);
    let pins = loader_pins(&set);
    let views = version_views(&set, &pins);
    let expected = retained_owner(&set, &views);
    let objects = set.referenced_objects().unwrap();
    assert_eq!(objects.len(), 5);
    assert_eq!(
        objects
            .iter()
            .filter(|object| object.versions.len() == 2)
            .count(),
        4
    );
    let unique = objects
        .iter()
        .find(|object| object.manifest == adapter.id())
        .unwrap();
    assert_eq!(unique.versions, [next.commitment()]);
    set.verify_cached(&store, &expected, &mut read_budget())
        .unwrap();

    let db = rusqlite::Connection::open(dir.path().join("cache.sqlite")).unwrap();
    for corrupt in [false, true] {
        install(&store, &adapter, &bytes);
        let statement = if corrupt {
            "UPDATE cell_chunks_v1 SET bytes = zeroblob(length(bytes)) WHERE hash = ?1"
        } else {
            "DELETE FROM cell_chunks_v1 WHERE hash = ?1"
        };
        assert_eq!(
            db.execute(statement, [adapter.chunks()[0].sha256.as_slice()])
                .unwrap(),
            1
        );
        verify_version(&store, &original);
        let mut budget = read_budget();
        assert!(set.verify_cached(&store, &expected, &mut budget).is_err());
        assert_eq!(budget.usage().attempts_committed, 1);
        assert_eq!(budget.usage().manifests_committed, 5);
    }
}

#[test]
fn failed_read_consumes_each_original_reservation_and_retry_cannot_renew_it() {
    let (dir, store, original) = fixture();
    let (next, adapter, bytes) = with_adapter(&original);
    install(&store, &adapter, &bytes);
    let set = retained(vec![original, next]);
    let pins = loader_pins(&set);
    let views = version_views(&set, &pins);
    let expected = retained_owner(&set, &views);
    let total_bytes = 4 * PAYLOAD_BYTES + adapter.size();
    let committed = CellRetainedReadUsageV1 {
        attempts_committed: 1,
        manifests_committed: 5,
        payload_bytes_committed: total_bytes,
        chunks_committed: 15,
    };
    let db = rusqlite::Connection::open(dir.path().join("cache.sqlite")).unwrap();
    for limited in 0..4 {
        let mut budget = CellRetainedReadBudgetV1::new(
            Instant::now() + Duration::from_secs(10),
            if limited == 0 { 1 } else { 2 },
            if limited == 1 { 5 } else { 10 },
            if limited == 2 {
                total_bytes
            } else {
                2 * total_bytes
            },
            if limited == 3 { 15 } else { 30 },
        );
        assert_eq!(
            db.execute(
                "DELETE FROM cell_chunks_v1 WHERE hash = ?1",
                [adapter.chunks()[0].sha256.as_slice()]
            )
            .unwrap(),
            1
        );
        assert!(set.verify_cached(&store, &expected, &mut budget).is_err());
        assert_eq!(budget.usage(), committed);
        install(&store, &adapter, &bytes);
        set.verify_cached(&store, &expected, &mut read_budget())
            .unwrap();
        assert!(matches!(
            set.verify_cached(&store, &expected, &mut budget),
            Err(CellErrorV1::Invalid(
                "retained original read reservation exhausted"
            ))
        ));
        assert_eq!(budget.usage(), committed);
    }
}

#[test]
fn expired_read_deadline_refuses_even_a_complete_warm_cache() {
    let (_dir, store, original) = fixture();
    let set = retained(vec![original]);
    let pins = loader_pins(&set);
    let views = version_views(&set, &pins);
    let mut budget = CellRetainedReadBudgetV1::new(Instant::now(), 1, 4, 4 * PAYLOAD_BYTES, 12);
    assert!(set
        .verify_cached(&store, &retained_owner(&set, &views), &mut budget)
        .is_err());
    assert_eq!(budget.usage(), CellRetainedReadUsageV1::default());
}

#[test]
fn all_owner_metadata_is_admitted_before_any_cache_write_or_network_request() {
    let (_dir, _store, original) = fixture();
    let (next, _adapter, _bytes) = with_adapter(&original);
    let set = retained(vec![original, next]);
    let pins = loader_pins(&set);
    for mismatch in 0..4 {
        let mut changed = pins.clone();
        let (model, environment) = changed.last_mut().unwrap();
        match mismatch {
            0 => model.context.tokenizer[0] ^= 1,
            1 => environment.context.runtime[0] ^= 1,
            2 => environment.max_chunks = 5,
            3 => model.max_payload_bytes = 1,
            _ => unreachable!(),
        }
        let views = version_views(&set, &changed);
        assert_no_preflight_effects(
            &set,
            &retained_owner(&set, &views),
            network_options(32, 1_000_000),
            None,
        );
    }
}

#[test]
fn late_oversized_object_and_aggregate_fetch_limits_refuse_without_side_effects() {
    let (_dir, _store, original) = fixture();
    let (next, adapter, _bytes) = with_adapter(&original);
    assert!(
        next.manifests()
            .iter()
            .position(|manifest| manifest.id() == adapter.id())
            .unwrap()
            > 0
    );
    let set = retained(vec![original, next]);
    let pins = loader_pins(&set);
    let views = version_views(&set, &pins);
    let expected = retained_owner(&set, &views);
    for limit in 0..3 {
        let mut options = network_options(32, 1_000_000);
        match limit {
            0 => options.limits.peer.max_cell_bytes = PAYLOAD_BYTES,
            1 => options.limits.release.max_payload_bytes = 4 * PAYLOAD_BYTES + adapter.size() - 1,
            2 => options.limits.release.max_chunks = 14,
            _ => unreachable!(),
        }
        assert_no_preflight_effects(&set, &expected, options, None);
    }
}

#[test]
fn expired_or_cancelled_fetch_has_no_network_or_cache_effects() {
    let (_dir, _store, original) = fixture();
    let set = retained(vec![original]);
    let pins = loader_pins(&set);
    let views = version_views(&set, &pins);
    let expected = retained_owner(&set, &views);
    let mut options = network_options(32, 1_000_000);
    options.limits.release.deadline = Instant::now();
    assert_no_preflight_effects(&set, &expected, options, None);
    assert_no_preflight_effects(
        &set,
        &expected,
        network_options(32, 1_000_000),
        Some(&AtomicBool::new(true)),
    );
}

#[test]
fn native_tcp_recovers_every_retained_version_with_one_shared_exact_quota() {
    let (dir, origin, original) = fixture();
    let (next, adapter, bytes) = with_adapter(&original);
    install(&origin, &adapter, &bytes);
    let (requests, response_bytes) = wire_cost(&next);
    assert_eq!(requests, 20);
    let set = retained(vec![original, next]);
    let pins = loader_pins(&set);
    let views = version_views(&set, &pins);
    let receiver_path = dir.path().join("receiver.sqlite");
    let receiver = empty_store(&receiver_path);
    let server = Server::start(&dir.path().join("cache.sqlite"), requests, response_bytes);
    let observation = fetch_retained_version_set(
        &receiver,
        &set,
        &retained_owner(&set, &views),
        &[server.address],
        network_options(requests, response_bytes),
        None,
    )
    .unwrap();
    let usage = observation.usage();
    assert_eq!((usage.connection_attempts, usage.request_attempts), (1, 20));
    assert_eq!(usage.received_response_bytes, Some(response_bytes));
    assert_eq!(
        (
            usage.completed_manifests,
            usage.downloaded_chunks,
            usage.cached_chunks
        ),
        (5, 15, 0),
    );
    let readback = observation.readback();
    assert_eq!(readback.versions().len(), 2);
    assert_eq!(
        (
            readback.manifests(),
            readback.payload_bytes(),
            readback.chunks()
        ),
        (5, 4 * PAYLOAD_BYTES + adapter.size(), 15),
    );
    for entry in set.entries() {
        verify_version(&receiver, &entry.version);
    }
    let served = server.finish();
    assert_eq!(served.request_attempts, 20);
    assert_eq!(served.serving.accepted_connections, 1);
    assert_eq!(served.serving.sent_response_bytes, response_bytes);
}

#[test]
fn native_tcp_does_not_reset_frame_or_response_quota_between_versions() {
    let (dir, origin, original) = fixture();
    let (next, adapter, bytes) = with_adapter(&original);
    install(&origin, &adapter, &bytes);
    let (requests, response_bytes) = wire_cost(&next);
    let set = retained(vec![original, next]);
    let pins = loader_pins(&set);
    let views = version_views(&set, &pins);
    for limit_frames in [true, false] {
        let path = dir.path().join(if limit_frames {
            "frame-limit.sqlite"
        } else {
            "response-limit.sqlite"
        });
        let receiver = empty_store(&path);
        let server = Server::start(&dir.path().join("cache.sqlite"), requests, response_bytes);
        let options = network_options(
            requests - u64::from(limit_frames),
            response_bytes - u64::from(!limit_frames),
        );
        let failure = fetch_retained_version_set(
            &receiver,
            &set,
            &retained_owner(&set, &views),
            &[server.address],
            options,
            None,
        )
        .unwrap_err();
        assert_eq!(failure.usage.connection_attempts, 1);
        assert!(failure.usage.request_attempts <= requests - u64::from(limit_frames));
        let received = failure.usage.received_response_bytes.unwrap();
        assert!(received > 0 && received <= options.limits.peer.max_response_bytes);
        assert!(failure.usage.completed_manifests < 5);
        assert!(set
            .verify_cached(&receiver, &retained_owner(&set, &views), &mut read_budget())
            .is_err());
        if limit_frames {
            assert_eq!(failure.usage.request_attempts, requests - 1);
        }
        let served = server.finish();
        assert_eq!(served.serving.accepted_connections, 1);
        assert!(served.request_attempts <= requests);
    }
}

#[test]
fn native_tcp_missing_required_version_object_cannot_return_whole_set_success() {
    let (dir, origin, original) = fixture();
    let (next, adapter, _bytes) = with_adapter(&original);
    verify_version(&origin, &original);
    assert!(origin.manifest(adapter.id()).unwrap().is_none());
    let (requests, response_bytes) = wire_cost(&next);
    let missing_index = next
        .manifests()
        .iter()
        .position(|manifest| manifest.id() == adapter.id())
        .unwrap();
    let expected_frames = missing_index as u64 + 1;
    let expected_response_bytes = 9 + next.manifests()[..missing_index]
        .iter()
        .map(|manifest| 9 + manifest.encode().len() as u64)
        .sum::<u64>();
    let set = retained(vec![original, next]);
    let pins = loader_pins(&set);
    let views = version_views(&set, &pins);
    let path = dir.path().join("incomplete-receiver.sqlite");
    let receiver = empty_store(&path);
    let server = Server::start(&dir.path().join("cache.sqlite"), requests, response_bytes);
    let failure = fetch_retained_version_set(
        &receiver,
        &set,
        &retained_owner(&set, &views),
        &[server.address],
        network_options(requests, response_bytes),
        None,
    )
    .unwrap_err();
    assert_eq!(failure.usage.connection_attempts, 1);
    assert_eq!(failure.usage.request_attempts, expected_frames);
    assert!(failure.usage.request_attempts <= requests);
    assert_eq!(
        failure.usage.received_response_bytes,
        Some(expected_response_bytes)
    );
    assert_eq!(
        (
            failure.usage.completed_manifests,
            failure.usage.downloaded_chunks
        ),
        (0, 0)
    );
    // Metadata can form a verified prefix; no payload starts before the entire
    // actual manifest set has been found and checked.
    let (manifests, chunks) = cache_rows(&path);
    assert_eq!(manifests, missing_index as u64);
    assert_eq!(chunks, 0);
    assert!(set
        .verify_cached(&receiver, &retained_owner(&set, &views), &mut read_budget())
        .is_err());
    let served = server.finish();
    assert_eq!(served.serving.accepted_connections, 1);
    assert_eq!(served.serving.completed_requests, expected_frames);
    assert_eq!(served.serving.sent_response_bytes, expected_response_bytes);
    // The server charges a read slot before waiting for the next frame. It
    // may admit one final read before client EOF or shutdown is observed;
    // that read is not another client probe or a completed response.
    assert!((expected_frames..=expected_frames + 1).contains(&served.request_attempts));
    assert!(served.request_attempts <= requests);
}
