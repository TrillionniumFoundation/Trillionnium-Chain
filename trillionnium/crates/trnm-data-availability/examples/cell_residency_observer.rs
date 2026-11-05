//! Finite native TCP -> fixed cache -> local-byte residency observation.
//!
//! These synthetic files are not tensors or a model. The ordinary Hepta loader,
//! CURRENT, FinalUse, device allocation and inference are not exercised. The
//! provider is stopped and joined before the 1,000 local accesses. Counts below
//! are byte-path observations, not latency percentiles or a WAN throughput gate.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs,
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use trnm_data_availability::cell::{
    digest_hex, serve_cells_bounded, CellCacheConfigV4, CellClosureFileV1, CellContextV1,
    CellErrorV1, CellFileRoleV1, CellLoaderContextV1, CellManifestV1, CellPeerLimitsV1,
    CellReleaseClosureV1, CellReleaseFetchLimitsV1, CellReleaseLimitsV1, CellResidencyConfigV1,
    CellResidencyV1, CellResidentFileV1, CellResultV1, CellServeLimitsV1, CellServeReportV1,
    CellStoreV1,
};

const BASE_BYTES: usize = 64 * 1024;
const TOKENIZER_BYTES: usize = 1024;
const ADAPTER_BYTES: usize = 4096;
const CHUNK_BYTES: u32 = 16 * 1024;
const HOT_ACCESSES: u64 = 1000;
const OPERATION_WINDOW: Duration = Duration::from_secs(10);
const SOURCE: &[u8] = include_bytes!("cell_residency_observer.rs");

fn require(condition: bool, reason: &'static str) -> CellResultV1<()> {
    if condition {
        Ok(())
    } else {
        Err(CellErrorV1::Invalid(reason))
    }
}

fn cache_config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 8 * 1024 * 1024,
        max_logical_bytes: 4 * 1024 * 1024,
        max_chunk_rows: 64,
        max_manifest_rows: 16,
    }
}

fn residency_config() -> CellResidencyConfigV1 {
    CellResidencyConfigV1 {
        max_resident_bytes: 2 * BASE_BYTES as u64,
        max_resident_closures: 2,
        max_chunk_references: 16,
    }
}

fn fetch_limits(deadline: Instant) -> CellReleaseFetchLimitsV1 {
    CellReleaseFetchLimitsV1 {
        peer: CellPeerLimitsV1 {
            request_timeout: Duration::from_secs(1),
            overall_timeout: OPERATION_WINDOW,
            max_cell_bytes: BASE_BYTES as u64,
            parallelism: 2,
            max_connections: 64,
            max_response_bytes: 1024 * 1024,
        },
        release: CellReleaseLimitsV1 {
            max_payload_bytes: (BASE_BYTES + TOKENIZER_BYTES + ADAPTER_BYTES) as u64,
            max_chunks: 6,
            deadline,
        },
    }
}

struct Provider {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<CellResultV1<CellServeReportV1>>>,
}

impl Provider {
    fn start(cache: &Path) -> CellResultV1<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let cache = cache.to_path_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("cell-residency-provider".into())
            .spawn(move || {
                serve_cells_bounded(
                    &listener,
                    &cache,
                    &shutdown,
                    CellServeLimitsV1 {
                        request_timeout: Duration::from_secs(1),
                        overall_timeout: Duration::from_secs(30),
                        max_workers: 4,
                        max_connections: 128,
                        max_response_bytes: 2 * 1024 * 1024,
                    },
                )
            })?;
        Ok(Self {
            address,
            stop,
            handle: Some(handle),
        })
    }

    fn finish(mut self) -> CellResultV1<CellServeReportV1> {
        self.stop.store(true, Ordering::Release);
        self.handle
            .take()
            .ok_or(CellErrorV1::Invalid("provider already joined"))?
            .join()
            .map_err(|_| CellErrorV1::Invalid("provider panicked"))?
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn pack(
    store: &CellStoreV1,
    directory: &Path,
    name: &str,
    bytes: &[u8],
    context: &CellContextV1,
) -> CellResultV1<CellManifestV1> {
    let path = directory.join(name);
    fs::write(&path, bytes)?;
    store.pack_file(&path, context.clone(), CHUNK_BYTES)
}

fn fixture(
    generation: u64,
    adapter: &CellManifestV1,
    base: &CellManifestV1,
    tokenizer: &CellManifestV1,
) -> CellResultV1<(CellReleaseClosureV1, CellLoaderContextV1)> {
    let files = [
        ("adapter.bin", CellFileRoleV1::Adapter, adapter, vec![1, 2]),
        ("base.bin", CellFileRoleV1::Base, base, vec![]),
        (
            "tokenizer.json",
            CellFileRoleV1::Tokenizer,
            tokenizer,
            vec![],
        ),
    ]
    .into_iter()
    .map(|(path, role, manifest, dependencies)| CellClosureFileV1 {
        path: path.into(),
        role,
        manifest: manifest.id(),
        payload_sha256: manifest.payload_sha256(),
        payload_bytes: manifest.size(),
        dependencies,
    })
    .collect();
    let closure = CellReleaseClosureV1::new(
        base.context().clone(),
        generation,
        Sha256::digest(b"synthetic-byte-staging-profile-v1").into(),
        vec![0],
        files,
    )?;
    let expected = CellLoaderContextV1 {
        closure_id: closure.id(),
        context: base.context().clone(),
        selected_generation: generation,
        loader_profile: closure.loader_profile(),
        required_roles: vec![
            CellFileRoleV1::Base,
            CellFileRoleV1::Tokenizer,
            CellFileRoleV1::Adapter,
        ],
        max_payload_bytes: (BASE_BYTES + TOKENIZER_BYTES + ADAPTER_BYTES) as u64,
        max_chunks: 6,
    };
    Ok((closure, expected))
}

fn verify_files(files: &[CellResidentFileV1], closure: &CellReleaseClosureV1) -> CellResultV1<u64> {
    require(files.len() == closure.files().len(), "resident file count")?;
    let mut total = 0;
    for (file, declared) in files.iter().zip(closure.files()) {
        require(
            file.path() == declared.path
                && file.role() == declared.role
                && file.manifest_id() == declared.manifest
                && file.payload_sha256() == declared.payload_sha256,
            "resident file identity",
        )?;
        let mut hash = Sha256::new();
        let mut size = 0;
        for chunk in file.chunks() {
            hash.update(chunk);
            size += chunk.len() as u64;
        }
        require(
            size == declared.payload_bytes
                && <[u8; 32]>::from(hash.finalize()) == declared.payload_sha256,
            "resident complete payload readback",
        )?;
        total += size;
    }
    Ok(total)
}

fn shared_base_buffers(files: &[CellResidentFileV1]) -> Vec<(usize, usize)> {
    files
        .iter()
        .filter(|file| file.role() == CellFileRoleV1::Base)
        .flat_map(|file| {
            file.chunks()
                .map(|bytes| (bytes.as_ptr() as usize, bytes.len()))
        })
        .collect()
}

fn rejection<T>(result: CellResultV1<T>) -> CellResultV1<String> {
    match result {
        Ok(_) => Err(CellErrorV1::Invalid(
            "expected refusal unexpectedly succeeded",
        )),
        Err(error) => Ok(error.to_string()),
    }
}

fn observe() -> Result<Value, Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let source_path = temporary.path().join("source.sqlite");
    let source = CellStoreV1::open(&source_path, cache_config())?;
    let base_bytes: Vec<_> = (0..BASE_BYTES)
        .map(|index| ((index * 17 + index / CHUNK_BYTES as usize * 29) % 251) as u8)
        .collect();
    let tokenizer_bytes = vec![b't'; TOKENIZER_BYTES];
    let context = CellContextV1 {
        family: "residency-byte-fixture-v1".into(),
        base: Sha256::digest(&base_bytes).into(),
        parent: Sha256::digest(b"fixture-parent").into(),
        tokenizer: Sha256::digest(&tokenizer_bytes).into(),
        layout: Sha256::digest(b"fixture-layout").into(),
        runtime: Sha256::digest(b"fixture-runtime").into(),
    };
    let base = pack(&source, temporary.path(), "base.bin", &base_bytes, &context)?;
    let tokenizer = pack(
        &source,
        temporary.path(),
        "tokenizer.json",
        &tokenizer_bytes,
        &context,
    )?;
    let adapter_a = pack(
        &source,
        temporary.path(),
        "adapter-a.bin",
        &[11; ADAPTER_BYTES],
        &context,
    )?;
    let adapter_b = pack(
        &source,
        temporary.path(),
        "adapter-b.bin",
        &[17; ADAPTER_BYTES],
        &context,
    )?;
    let (closure_a, expected_a) = fixture(1, &adapter_a, &base, &tokenizer)?;
    let (closure_b, expected_b) = fixture(2, &adapter_b, &base, &tokenizer)?;
    drop(source);

    let provider = Provider::start(&source_path)?;
    let peers = [provider.address];
    let cache = CellStoreV1::open(&temporary.path().join("consumer.sqlite"), cache_config())?;
    require(cache.cache_usage()?.chunk_rows == 0, "cold cache not empty")?;
    let mut resident = CellResidencyV1::new(residency_config())?;
    let cancelled = AtomicBool::new(false);
    let download_deadline = Instant::now() + OPERATION_WINDOW;
    let cold = resident
        .prefetch(
            &cache,
            &closure_a,
            &expected_a,
            &peers,
            fetch_limits(download_deadline),
            &cancelled,
        )?
        .fetch
        .ok_or(CellErrorV1::Invalid("cold observation did not fetch"))?;
    require(
        cold.release.downloaded_bytes == expected_a.max_payload_bytes
            && cold.release.cached_chunks == 0
            && cold.release.connection_attempts > 0,
        "cold acquisition counters",
    )?;
    resident.pin_hot(&expected_a)?;
    let selected_a = resident.select_local(
        None,
        &expected_a,
        Instant::now() + OPERATION_WINDOW,
        &cancelled,
    )?;

    // The explicit routing hint owns this preparation. It does not select B.
    // Both downloads share the one original absolute window above.
    let prefetched = resident
        .prefetch(
            &cache,
            &closure_b,
            &expected_b,
            &peers,
            fetch_limits(download_deadline),
            &cancelled,
        )?
        .fetch
        .ok_or(CellErrorV1::Invalid("route observation did not fetch"))?;
    require(
        prefetched.release.downloaded_bytes == ADAPTER_BYTES as u64
            && prefetched.release.cached_chunks == 5
            && resident.selection() == Some(selected_a),
        "route prefetch shared-base/selection counters",
    )?;
    let served = provider.finish()?;

    let local_deadline = Instant::now() + OPERATION_WINDOW;
    let base_a = resident.with_local(&expected_a, local_deadline, |view| {
        shared_base_buffers(view.files())
    })?;
    let base_b = resident.with_local(&expected_b, local_deadline, |view| {
        shared_base_buffers(view.files())
    })?;
    require(
        base_a.len() == 4 && base_a == base_b,
        "base buffers were copied per release",
    )?;
    let usage = resident.usage();
    require(
        usage.unique_payload_bytes == (BASE_BYTES + TOKENIZER_BYTES + 2 * ADAPTER_BYTES) as u64
            && usage.unique_chunks == 7
            && usage.resident_closures == 2
            && usage.chunk_references == 12,
        "resident deduplication accounting",
    )?;
    let mut hot_bytes = 0;
    for _ in 0..HOT_ACCESSES {
        hot_bytes += resident.with_selected(&expected_a, local_deadline, |view| {
            verify_files(view.files(), &closure_a)
        })??;
    }
    let selected_b =
        resident.select_local(Some(selected_a), &expected_b, local_deadline, &cancelled)?;
    resident.with_selected(&expected_b, local_deadline, |view| {
        verify_files(view.files(), &closure_b)
    })??;
    let already_resident = resident.prefetch(
        &cache,
        &closure_b,
        &expected_b,
        &[],
        fetch_limits(local_deadline),
        &cancelled,
    )?;
    require(
        already_resident.fetch.is_none(),
        "resident hit attempted acquisition",
    )?;

    // A fresh manager can prepare the fixed disk version with no peer argument.
    let mut disk_warm = CellResidencyV1::new(residency_config())?;
    disk_warm.prepare_cached(&cache, &closure_a, &expected_a, local_deadline, &cancelled)?;
    disk_warm.with_local(&expected_a, local_deadline, |view| {
        verify_files(view.files(), &closure_a)
    })??;
    let cold_miss = rejection(disk_warm.with_local(&expected_b, local_deadline, |_| ()))?;
    let stale_selection = rejection(resident.select_local(
        Some(selected_a),
        &expected_a,
        local_deadline,
        &cancelled,
    ))?;
    let expired = Instant::now() - Duration::from_millis(1);
    let expired_switch =
        rejection(resident.select_local(Some(selected_b), &expected_a, expired, &cancelled))?;
    let expired_download = rejection(resident.prefetch(
        &cache,
        &closure_b,
        &expected_b,
        &peers,
        fetch_limits(expired),
        &cancelled,
    ))?;
    let cancelled_switch = rejection(resident.select_local(
        Some(selected_b),
        &expected_a,
        local_deadline,
        &AtomicBool::new(true),
    ))?;
    let hot_eviction = rejection(resident.evict(expected_a.closure_id))?;
    let selected_eviction = rejection(resident.evict(expected_b.closure_id))?;
    let mut wrong_version = expected_b.clone();
    wrong_version.selected_generation += 1;
    let wrong_version = rejection(resident.with_local(&wrong_version, local_deadline, |_| ()))?;
    let mut quota = CellResidencyV1::new(CellResidencyConfigV1 {
        max_resident_bytes: expected_a.max_payload_bytes - 1,
        ..residency_config()
    })?;
    let quota_rejection = rejection(quota.prepare_cached(
        &cache,
        &closure_a,
        &expected_a,
        local_deadline,
        &cancelled,
    ))?;
    require(
        quota.usage().resident_closures == 0 && resident.selection() == Some(selected_b),
        "rejected operation changed residency or selection",
    )?;
    resident.unpin_hot(expected_a.closure_id)?;
    resident.evict(expected_a.closure_id)?;
    let after_eviction = resident.usage();
    require(
        after_eviction.unique_payload_bytes == expected_b.max_payload_bytes
            && after_eviction.unique_chunks == 6
            && after_eviction.resident_closures == 1
            && after_eviction.chunk_references == 6,
        "eviction removed shared bytes or retained the old adapter",
    )?;
    resident.with_selected(&expected_b, local_deadline, |view| {
        verify_files(view.files(), &closure_b)
    })??;

    Ok(json!({
        "schema": "cell-residency-byte-observation-v1",
        "result": "PASS",
        "observer_source_sha256": digest_hex(Sha256::digest(SOURCE).into()),
        "fixture": {"closures": 2, "files_per_closure": 3, "base_bytes": BASE_BYTES,
            "tokenizer_bytes": TOKENIZER_BYTES, "adapter_bytes_per_version": ADAPTER_BYTES,
            "closure_ids": [digest_hex(closure_a.id()), digest_hex(closure_b.id())]},
        "cold": {"downloaded_bytes": cold.release.downloaded_bytes,
            "downloaded_chunks": cold.release.downloaded_chunks,
            "connection_attempts": cold.release.connection_attempts,
            "received_response_bytes": cold.release.received_response_bytes},
        "route_prefetch": {"downloaded_bytes": prefetched.release.downloaded_bytes,
            "downloaded_chunks": prefetched.release.downloaded_chunks,
            "cached_chunks": prefetched.release.cached_chunks,
            "connection_attempts": prefetched.release.connection_attempts,
            "received_response_bytes": prefetched.release.received_response_bytes,
            "preserved_previous_selection": true},
        "provider": {"stopped_and_joined_before_hot_access": true,
            "accepted_connections": served.accepted_connections,
            "completed_requests": served.completed_requests,
            "sent_response_bytes": served.sent_response_bytes},
        "local": {"hot_accesses": HOT_ACCESSES, "rehashed_payload_bytes": hot_bytes,
            "base_buffers_shared_between_closures": base_a.len(),
            "unique_payload_bytes": usage.unique_payload_bytes,
            "unique_chunks": usage.unique_chunks, "chunk_references": usage.chunk_references,
            "resident_closures": usage.resident_closures, "resident_hit_fetch": false,
            "fixed_disk_version_prepared_without_peers": true, "selected_generation": 2},
        "after_old_version_eviction": {"unique_payload_bytes": after_eviction.unique_payload_bytes,
            "unique_chunks": after_eviction.unique_chunks, "chunk_references": after_eviction.chunk_references,
            "resident_closures": after_eviction.resident_closures,
            "selected_shared_base_readback": true},
        "refusals": {"cold_local_miss": cold_miss, "stale_selection": stale_selection,
            "expired_switch": expired_switch, "expired_download": expired_download,
            "cancelled_switch": cancelled_switch, "hot_eviction": hot_eviction,
            "selected_eviction": selected_eviction,
            "wrong_generation": wrong_version, "resident_quota": quota_rejection},
        "scope": "synthetic byte staging; explicit route hint; loopback TCP; no model forward",
        "exclusions": "no real router predictor, tensors, GPU allocation, CURRENT, FinalUse, KV/activation transport, distributed inference, WAN or latency percentile qualification; observer source hash alone is not the full build receipt"
    }))
}

fn main() -> Result<(), Box<dyn Error>> {
    let observation = observe();
    let failed = observation.is_err();
    let record = observation.unwrap_or_else(|error| {
        json!({"schema": "cell-residency-byte-observation-v1", "result": "FAIL",
            "observer_source_sha256": digest_hex(Sha256::digest(SOURCE).into()),
            "error": error.to_string(), "completed_observation": false})
    });
    println!("{}", serde_json::to_string(&record)?);
    if failed {
        std::process::exit(1);
    }
    Ok(())
}
