//! Finite synthetic fixed-base TCX1/CAS observations, including losing cases.
//! Each group uses actual cache packing, a ready-gated loopback provider,
//! original delta retrieval, complete hashes and create-only materialization.
//! This is not a model workload distribution, WAN campaign or retention proof.

use std::{
    error::Error,
    fs, io,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use trnm_data_availability::cell::{
    digest_hex, fetch_delta_to_file, serve_cells_bounded_with_ready, CellCacheConfigV4,
    CellChunkDeltaV1, CellContextV1, CellErrorV1, CellManifestV1, CellPeerLimitsV1,
    CellReleaseFetchLimitsV1, CellReleaseLimitsV1, CellResultV1, CellServeLimitsV1,
    CellServeReportV1, CellStoreV1,
};

type ObservationResult<T> = Result<T, Box<dyn Error>>;

const CHUNK_BYTES: usize = 16 * 1024;
const PAYLOAD_BYTES: usize = 256 * 1024;
const VERSIONS: usize = 9;
const READY_TIMEOUT: Duration = Duration::from_secs(15);
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const SERVE_TIMEOUT: Duration = Duration::from_secs(120);
const SOURCE: &[u8] = include_bytes!("cell_delta_workload_observer.rs");
const WORKLOADS: [&str; 5] = [
    "identical",
    "single-chunk-sparse-change",
    "chunk-reordering",
    "one-to-eight-byte-shift",
    "dense-full-change",
];

fn config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 32 * 1024 * 1024,
        max_logical_bytes: 16 * 1024 * 1024,
        max_chunk_rows: 4096,
        max_manifest_rows: 256,
    }
}

fn limits() -> CellReleaseFetchLimitsV1 {
    CellReleaseFetchLimitsV1 {
        peer: CellPeerLimitsV1 {
            request_timeout: Duration::from_secs(2),
            overall_timeout: FETCH_TIMEOUT,
            max_cell_bytes: PAYLOAD_BYTES as u64,
            parallelism: 2,
            max_connections: 64,
            max_response_bytes: (2 * PAYLOAD_BYTES + 4096) as u64,
        },
        release: CellReleaseLimitsV1 {
            max_payload_bytes: 2 * PAYLOAD_BYTES as u64,
            max_chunks: 2 * (PAYLOAD_BYTES / CHUNK_BYTES) as u64,
            deadline: Instant::now() + FETCH_TIMEOUT,
        },
    }
}

fn bytes(seed: u64, count: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(count);
    for block in 0..count.div_ceil(32) {
        let mut hash = Sha256::new();
        hash.update(b"trnm.cell-delta-workload.fixture.v1\0");
        hash.update(seed.to_le_bytes());
        hash.update((block as u64).to_le_bytes());
        let block = hash.finalize();
        let remaining = count - result.len();
        result.extend_from_slice(&block[..remaining.min(32)]);
    }
    result
}

fn target(workload: &str, version: usize, base: &[u8]) -> Vec<u8> {
    if version == 0 {
        return base.to_vec();
    }
    let mut result = base.to_vec();
    match workload {
        "identical" => (),
        "single-chunk-sparse-change" => {
            let start = (version - 1) * CHUNK_BYTES;
            result[start..start + CHUNK_BYTES]
                .copy_from_slice(&bytes(100 + version as u64, CHUNK_BYTES));
        }
        "chunk-reordering" => result.rotate_left(version * CHUNK_BYTES),
        "one-to-eight-byte-shift" => result.rotate_left(version),
        "dense-full-change" => result = bytes(200 + version as u64, PAYLOAD_BYTES),
        _ => unreachable!("fixed declared workload roster"),
    }
    result
}

fn context(base: &[u8]) -> CellContextV1 {
    CellContextV1 {
        family: "synthetic-fixed-base-delta-observer-v1".into(),
        base: Sha256::digest(base).into(),
        parent: Sha256::digest(b"synthetic-delta-origin-v1").into(),
        tokenizer: Sha256::digest(b"synthetic-no-tokenizer-profile-v1").into(),
        layout: Sha256::digest(b"synthetic-raw-byte-layout-v1").into(),
        runtime: Sha256::digest(b"synthetic-no-model-execution-v1").into(),
    }
}

struct Provider {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<CellResultV1<CellServeReportV1>>>,
}

impl Provider {
    fn start(path: &Path) -> ObservationResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let path = path.to_path_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let (ready_tx, ready_rx) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("delta-workload-provider".into())
            .spawn(move || {
                serve_cells_bounded_with_ready(
                    &listener,
                    &path,
                    &shutdown,
                    CellServeLimitsV1 {
                        request_timeout: Duration::from_secs(2),
                        overall_timeout: SERVE_TIMEOUT,
                        max_workers: 4,
                        max_connections: 512,
                        max_response_bytes: 8 * 1024 * 1024,
                    },
                    &|| {
                        ready_tx.send(()).map_err(|_| {
                            CellErrorV1::Invalid("delta observer readiness receiver gone")
                        })
                    },
                )
            })?;
        let provider = Self {
            address,
            stop,
            handle: Some(handle),
        };
        if let Err(error) = ready_rx.recv_timeout(READY_TIMEOUT) {
            let service = provider.finish();
            return Err(format!("provider readiness: {error}; service: {service:?}").into());
        }
        Ok(provider)
    }

    fn finish(mut self) -> ObservationResult<CellServeReportV1> {
        self.stop.store(true, Ordering::Release);
        let handle = self
            .handle
            .take()
            .ok_or_else(|| io::Error::other("provider already joined"))?;
        Ok(handle
            .join()
            .map_err(|_| io::Error::other("provider thread panicked"))??)
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

fn file_length(path: &Path) -> ObservationResult<Value> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(json!({"exists": true, "file_length_bytes": metadata.len()})),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(json!({"exists": false, "file_length_bytes": 0}))
        }
        Err(error) => Err(error.into()),
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    value.into()
}

/// Every writer/server/query connection has closed before file lengths are read.
/// SQL totals are an independent readback of the cache's actual stored objects;
/// file length is neither allocated filesystem blocks nor peak storage usage.
fn cache_snapshot(path: &Path) -> ObservationResult<Value> {
    let checked = CellStoreV1::open_read_only(path)?;
    let usage = checked.cache_usage()?;
    drop(checked);
    let database = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let (chunk_rows, payload_bytes): (u64, u64) = database.query_row(
        "SELECT count(*),coalesce(sum(length(bytes)),0) FROM cell_chunks_v1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (manifest_rows, manifest_wire_bytes): (u64, u64) = database.query_row(
        "SELECT count(*),coalesce(sum(length(wire)),0) FROM cell_manifests_v1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    drop(database);
    let key_bytes = (chunk_rows + manifest_rows) * 32;
    if chunk_rows != usage.chunk_rows
        || manifest_rows != usage.manifest_rows
        || payload_bytes + manifest_wire_bytes + key_bytes != usage.logical_bytes
    {
        return Err("observed cache accounting does not match exact stored rows".into());
    }
    let main = file_length(path)?;
    let wal = file_length(&sidecar(path, "-wal"))?;
    let shm = file_length(&sidecar(path, "-shm"))?;
    let total = [&main, &wal, &shm]
        .iter()
        .map(|entry| entry["file_length_bytes"].as_u64().unwrap())
        .sum::<u64>();
    Ok(json!({
        "unique_payload_bytes": payload_bytes,
        "unique_chunk_rows": chunk_rows,
        "manifest_rows": manifest_rows,
        "manifest_wire_bytes": manifest_wire_bytes,
        "key_logical_bytes": key_bytes,
        "total_logical_bytes": usage.logical_bytes,
        "closed_cache_files": {"main": main, "wal": wal, "shm": shm},
        "closed_cache_file_length_sum_bytes": total,
    }))
}

fn version_observation(
    client: &CellStoreV1,
    base: &CellManifestV1,
    target: &CellManifestV1,
    expected_bytes: &[u8],
    peer: SocketAddr,
    output: &Path,
    version: usize,
) -> Value {
    let mut observation = json!({
        "version": version, "status": "failed", "error": null,
        "base_manifest": digest_hex(base.id()), "target_manifest": digest_hex(target.id()),
        "target_payload_sha256": digest_hex(target.payload_sha256()),
        "reconstruction_depth": 1,
        "actual_transport": null,
    });
    let result = (|| -> ObservationResult<()> {
        let delta = CellChunkDeltaV1::between(base, target)?;
        let wire = delta.encode();
        let decoded = CellChunkDeltaV1::decode(&wire)?;
        let plan = decoded.verify(base)?;
        observation["delta_id"] = json!(digest_hex(decoded.id()));
        observation["delta_wire_bytes"] = json!(wire.len());
        observation["fixed_base_plan"] = json!({
            "reused_chunk_positions": plan.reused_chunks, "reused_bytes": plan.reused_bytes,
            "new_chunk_positions": plan.new_chunks, "new_bytes": plan.new_bytes,
        });
        let (actual_plan, report) = fetch_delta_to_file(
            client,
            &decoded,
            (decoded.id(), base.id(), target.id()),
            &[peer],
            limits(),
            output,
        )?;
        observation["actual_transport"] = json!({
            "cached_chunk_positions": report.cached_chunks,
            "downloaded_chunk_positions": report.downloaded_chunks,
            "downloaded_payload_bytes": report.downloaded_bytes,
            "received_response_bytes": report.received_response_bytes,
            "connection_attempts": report.connection_attempts,
            "rejected_responses": report.rejected_responses,
            "supplying_peers": report.supplying_peers.len(),
        });
        if actual_plan != plan
            || report.manifest_id != target.id()
            || report.payload_sha256 != target.payload_sha256()
            || report.payload_bytes != PAYLOAD_BYTES as u64
            || report.cached_chunks + report.downloaded_chunks != target.chunks().len()
        {
            return Err("delta report identity or chunk coverage mismatch".into());
        }
        let materialized = fs::read(output)?;
        let digest: [u8; 32] = Sha256::digest(&materialized).into();
        observation["materialized_bytes"] = json!(materialized.len());
        observation["materialized_sha256"] = json!(digest_hex(digest));
        if materialized != expected_bytes || digest != target.payload_sha256() {
            return Err("materialized target bytes/hash mismatch".into());
        }
        client.verify_complete(target)?;
        client.verify_complete(base)?;
        observation["status"] = json!("passed");
        Ok(())
    })();
    if let Err(error) = result {
        observation["error"] = json!(error.to_string());
    }
    match client.cache_usage() {
        Ok(usage) => {
            observation["cache_after_attempt"] = json!({
                "logical_bytes": usage.logical_bytes,
                "chunk_rows": usage.chunk_rows, "manifest_rows": usage.manifest_rows,
            });
        }
        Err(error) => {
            observation["cache_after_attempt_error"] = json!(error.to_string());
            observation["status"] = json!("failed");
        }
    }
    observation
}

fn observe_group(workload: &str) -> Value {
    let mut observation = json!({
        "workload": workload, "status": "failed", "errors": [], "versions": [],
        "full_copy_payload_baseline_bytes": VERSIONS * PAYLOAD_BYTES,
        "comparisons_complete": false,
    });
    if let Err(error) = run_group(workload, &mut observation) {
        observation["errors"]
            .as_array_mut()
            .unwrap()
            .push(json!(error.to_string()));
    }
    observation
}

fn run_group(workload: &str, observation: &mut Value) -> ObservationResult<()> {
    let temporary = tempfile::tempdir()?;
    let origin_path = temporary.path().join("origin.sqlite");
    let client_path = temporary.path().join("receiver.sqlite");
    let origin = CellStoreV1::open(&origin_path, config())?;
    let client = CellStoreV1::open(&client_path, config())?;
    let base_bytes = bytes(0, PAYLOAD_BYTES);
    let context = context(&base_bytes);
    let mut targets = Vec::with_capacity(VERSIONS);
    let mut payloads = Vec::with_capacity(VERSIONS);
    for version in 0..VERSIONS {
        let payload = target(workload, version, &base_bytes);
        let input = temporary.path().join(format!("version-{version}.input"));
        fs::write(&input, &payload)?;
        targets.push(origin.pack_file(&input, context.clone(), CHUNK_BYTES as u32)?);
        payloads.push(payload);
    }
    let base = client.pack_file(
        &temporary.path().join("version-0.input"),
        context,
        CHUNK_BYTES as u32,
    )?;
    if base.id() != targets[0].id() {
        return Err("initial receiver/source base mismatch".into());
    }
    observation["versions"].as_array_mut().unwrap().push(json!({
        "version": 0, "status": "passed", "kind": "initial-base-local-pack",
        "target_manifest": digest_hex(base.id()),
        "payload_sha256": digest_hex(base.payload_sha256()), "payload_bytes": base.size(),
        "actual_transport": null, "reconstruction_depth": 0,
    }));
    drop(origin);
    let provider = Provider::start(&origin_path)?;
    observation["provider_ready"] = json!({"channel_handoff": true, "probe_connections": 0});
    for version in 1..VERSIONS {
        let result = version_observation(
            &client,
            &base,
            &targets[version],
            &payloads[version],
            provider.address,
            &temporary
                .path()
                .join(format!("version-{version}.materialized")),
            version,
        );
        observation["versions"].as_array_mut().unwrap().push(result);
    }
    match provider.finish() {
        Ok(report) => {
            observation["provider_final"] = json!({
                "accepted_connections": report.accepted_connections,
                "overloaded_connections": report.overloaded_connections,
                "completed_requests": report.completed_requests,
                "peak_active_workers": report.peak_active_workers,
                "sent_response_bytes": report.sent_response_bytes,
            });
        }
        Err(error) => observation["errors"]
            .as_array_mut()
            .unwrap()
            .push(json!(format!("provider: {error}"))),
    }
    drop(client);
    for (name, path) in [
        ("origin_cache", origin_path),
        ("receiver_cache", client_path),
    ] {
        match cache_snapshot(&path) {
            Ok(snapshot) => observation[name] = snapshot,
            Err(error) => observation["errors"]
                .as_array_mut()
                .unwrap()
                .push(json!(format!("{name}: {error}"))),
        }
    }
    let versions = observation["versions"].as_array().unwrap();
    let all_versions_passed =
        versions.len() == VERSIONS && versions.iter().all(|version| version["status"] == "passed");
    let complete = all_versions_passed && observation["errors"].as_array().unwrap().is_empty();
    observation["comparisons_complete"] = json!(complete);
    if complete {
        let baseline = (VERSIONS * PAYLOAD_BYTES) as i64;
        let receiver = &observation["receiver_cache"];
        let comparison = json!({
            "unique_payload_saving_bytes": baseline - receiver["unique_payload_bytes"].as_i64().unwrap(),
            "logical_cache_minus_full_copy_payload_bytes": receiver["total_logical_bytes"].as_i64().unwrap() - baseline,
            "closed_file_lengths_minus_full_copy_payload_bytes": receiver["closed_cache_file_length_sum_bytes"].as_i64().unwrap() - baseline,
        });
        observation["cache_comparison"] = comparison;
        observation["status"] = json!("passed");
    }
    Ok(())
}

fn main() {
    let groups: Vec<_> = WORKLOADS.into_iter().map(observe_group).collect();
    let complete = groups.iter().all(|group| group["status"] == "passed");
    let cache = config();
    let report = json!({
        "schema": "trnm.cell-delta-workload-observation.v1",
        "source_sha256": digest_hex(Sha256::digest(SOURCE).into()),
        "os": std::env::consts::OS, "architecture": std::env::consts::ARCH,
        "status": if complete { "complete" } else { "failed_with_observations_retained" },
        "configuration": {
            "chunk_bytes": CHUNK_BYTES, "payload_bytes": PAYLOAD_BYTES,
            "versions_per_group_including_original_base": VERSIONS,
            "version_zero_base_for_every_delta": true, "maximum_reconstruction_depth": 1,
            "fixture_generator": "SHA256(domain || seed:u64le || block:u64le)",
            "original_base_seed": 0, "sparse_replacement_seed": "100 + version",
            "dense_target_seed": "200 + version",
            "ready_timeout_ms": READY_TIMEOUT.as_millis(),
            "fetch_operation_timeout_ms": FETCH_TIMEOUT.as_millis(),
            "serve_operation_timeout_ms": SERVE_TIMEOUT.as_millis(),
            "cache_max_database_bytes": cache.max_database_bytes,
            "cache_max_logical_bytes": cache.max_logical_bytes,
            "cache_max_chunk_rows": cache.max_chunk_rows,
            "cache_max_manifest_rows": cache.max_manifest_rows,
            "per_fetch_parallelism": 2, "per_fetch_max_connections": 64,
            "per_fetch_max_response_bytes": 2 * PAYLOAD_BYTES + 4096,
        },
        "scope": {
            "synthetic_finite_workloads_only": true, "transport": "actual loopback TCQ1/TCS1",
            "local_inputs": "initial base packed locally; TCX1 recipe with complete target manifest supplied locally",
            "response_bytes": "response frames only; excludes requests, TCP/IP and recipe distribution",
            "model_runtime_executed": false, "wan_qualification": false,
            "retention_or_custody_authority": false,
            "full_copy_baseline": "nine complete payload copies; excludes format/storage overhead",
            "logical_cache": "actual unique payload + manifest wire + all 32-byte keys",
            "file_lengths": "closed DB/WAL/SHM lengths; not allocated blocks or peak disk use",
            "excluded_from_cache_totals": "fixture input files, materialized output files, TCX1 recipes, directory entries and worker memory",
            "delta_depth": "each target directly pins original complete base; no recursive reconstruction chain",
            "failed_transport_counters": "null if native error returned no report; partial cache usage remains observed",
            "savings": "positive payload savings; positive logical/file-length deltas are overhead; no pass threshold on savings",
        },
        "groups": groups,
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    if !complete {
        std::process::exit(1);
    }
}
