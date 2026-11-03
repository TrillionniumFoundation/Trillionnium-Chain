//! Complete local Cell-service observation, not a throughput acceptance gate.
//!
//! Build this exact file in both original workspaces with --locked and the same
//! release profile. A coordinator runs sixteen A/B/B/A cohorts with fresh
//! processes and scratch directories; this executable performs one observation.
//! The source fixture, all probes, failed calls, materialization, independent
//! output hashes, close, shutdown and joins remain in the whole-run denominator.
//! "Cold" means an empty application cache; OS/device caches are not evicted.
//! Native fetch already includes connection, chunk/full hash and publication.
//! Its internal phases are not separately observable through the public API.
//! The explicit manifest probe measures its own TCP stages, never those hidden
//! fetch phases. This is one Cell, not a complete Hepta release or inference.

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use trnm_data_availability::cell::{
    digest_hex, fetch_cell_to_file, serve_cells_bounded, CellCacheConfigV4, CellContextV1,
    CellFetchReportV1, CellManifestV1, CellPeerLimitsV1, CellResultV1, CellServeLimitsV1,
    CellServeReportV1, CellStoreV1,
};

const PAIRS: usize = 8;
const PAYLOAD_BYTES: usize = 256 * 1024;
const CHUNK_BYTES: u32 = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const SERVICE_TIMEOUT: Duration = Duration::from_secs(30);
const OBSERVER_SOURCE: &[u8] = include_bytes!("cell_serving_ab_observer.rs");

fn cache_config() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 8 * 1024 * 1024,
        max_logical_bytes: 4 * 1024 * 1024,
        max_chunk_rows: 128,
        max_manifest_rows: 16,
    }
}

fn fetch_limits() -> CellPeerLimitsV1 {
    CellPeerLimitsV1 {
        request_timeout: REQUEST_TIMEOUT,
        overall_timeout: FETCH_TIMEOUT,
        max_cell_bytes: PAYLOAD_BYTES as u64,
        parallelism: 2,
        max_connections: 40,
        max_response_bytes: 2 * PAYLOAD_BYTES as u64 + 2 * 1_048_576 + 9 * 40,
    }
}

fn serving_limits() -> CellServeLimitsV1 {
    CellServeLimitsV1 {
        request_timeout: REQUEST_TIMEOUT,
        overall_timeout: SERVICE_TIMEOUT,
        max_workers: 4,
        max_connections: 512,
        max_response_bytes: 64 * 1024 * 1024,
    }
}

struct Recorder {
    origin: Instant,
    run_id: String,
    sequence: u64,
    write_error: Option<String>,
}

impl Recorder {
    fn emit(&mut self, kind: &str, data: Value) {
        let row = json!({
            "schema": "cell-serving-ab-observation-v1",
            "run_id": self.run_id,
            "sequence": self.sequence,
            "monotonic_ns": self.origin.elapsed().as_nanos(),
            "kind": kind,
            "data": data,
        });
        self.sequence += 1;
        let mut output = io::stdout().lock();
        let result = serde_json::to_writer(&mut output, &row)
            .map_err(io::Error::other)
            .and_then(|()| output.write_all(b"\n"))
            .and_then(|()| output.flush());
        if let Err(error) = result {
            self.write_error.get_or_insert_with(|| error.to_string());
        }
    }

    fn measure<T, E: std::fmt::Display>(
        &mut self,
        operation: &str,
        call: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.emit("stage_entered", json!({"operation": operation}));
        let started = Instant::now();
        let result = call();
        let finished = Instant::now();
        self.emit(
            "stage",
            json!({
                "operation": operation,
                "start_ns": started.duration_since(self.origin).as_nanos(),
                "end_ns": finished.duration_since(self.origin).as_nanos(),
                "wall_ns": finished.duration_since(started).as_nanos(),
                "success": result.is_ok(),
                "error": result.as_ref().err().map(ToString::to_string),
            }),
        );
        result
    }

    fn close<T>(&mut self, operation: &str, value: T) {
        let started = Instant::now();
        drop(value);
        let finished = Instant::now();
        self.emit(
            "stage",
            json!({
                "operation": operation,
                "start_ns": started.duration_since(self.origin).as_nanos(),
                "end_ns": finished.duration_since(self.origin).as_nanos(),
                "wall_ns": finished.duration_since(started).as_nanos(),
                "success": true,
                "scope": "owned-handle drop returned; no remote TCP acknowledgement or hidden SQLite close error is inferred",
            }),
        );
    }
}

#[derive(Default, Serialize)]
struct Totals {
    fetches_attempted: u64,
    fetches_succeeded: u64,
    fetch_errors: u64,
    expected_refusals: u64,
    unexpected_errors: u64,
    probes_attempted: u64,
    probes_succeeded: u64,
    verified_cold_output_bytes: u64,
    verified_warm_output_bytes: u64,
    successful_fetch_connection_attempts: u64,
    successful_fetch_rejected_responses: usize,
    successful_fetch_received_response_bytes: u64,
    failed_fetch_transport_counters_unknown: u64,
}

type ServiceObservation = (Instant, Instant, CellResultV1<CellServeReportV1>);

struct RunningService {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<ServiceObservation>>,
}

impl RunningService {
    fn start(listener: TcpListener, source: PathBuf) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("cell-observer-service".into())
            .spawn(move || {
                let started = Instant::now();
                let report = serve_cells_bounded(&listener, &source, &shutdown, serving_limits());
                (started, Instant::now(), report)
            })?;
        Ok(Self {
            stop,
            handle: Some(handle),
        })
    }

    fn finish(mut self, recorder: &mut Recorder) -> Result<Value, String> {
        self.stop.store(true, Ordering::Relaxed);
        let Some(handle) = self.handle.take() else {
            return Err("service handle absent".into());
        };
        let (started, finished, report) = recorder.measure("service.shutdown_and_drain", || {
            handle
                .join()
                .map_err(|_| "service thread panicked".to_string())
        })?;
        let report = report.map_err(|error| error.to_string())?;
        Ok(json!({
            "start_ns": started.duration_since(recorder.origin).as_nanos(),
            "end_ns": finished.duration_since(recorder.origin).as_nanos(),
            "wall_ns": finished.duration_since(started).as_nanos(),
            "accepted_connections": report.accepted_connections,
            "overloaded_connections": report.overloaded_connections,
            "completed_requests": report.completed_requests,
            "admitted_requests_without_complete_response": report.accepted_connections
                - report.overloaded_connections - report.completed_requests,
            "peak_active_workers": report.peak_active_workers,
            "sent_response_bytes": report.sent_response_bytes,
            "completed_request_scope": "a complete protocol response, including an absent-manifest response; not a complete Cell fetch",
        }))
    }
}

impl Drop for RunningService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            // Also drain on an observer panic/error; never leave a detached service.
            let _ = handle.join();
        }
    }
}

fn manifest_probe(
    recorder: &mut Recorder,
    address: SocketAddr,
    manifest: &CellManifestV1,
    fetch_id: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    let mut stream = recorder
        .measure(&format!("{fetch_id}.probe.connect"), || {
            TcpStream::connect_timeout(&address, REQUEST_TIMEOUT)
        })
        .map_err(|error| error.to_string())?;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    };
    let mut query = b"TCQ1\x01".to_vec();
    query.extend(manifest.id());
    let expected = manifest.encode();
    let result = (|| -> io::Result<()> {
        recorder.measure(&format!("{fetch_id}.probe.send"), || {
            stream.set_write_timeout(Some(remaining()?))?;
            stream.write_all(&query)
        })?;
        let mut received = Vec::new();
        let read = recorder.measure(&format!("{fetch_id}.probe.read_through_eof"), || {
            let mut buffer = [0_u8; 4096];
            loop {
                stream.set_read_timeout(Some(remaining()?))?;
                let count = stream.read(&mut buffer)?;
                if count == 0 {
                    return Ok::<_, io::Error>(());
                }
                received.extend_from_slice(&buffer[..count]);
                if received.len() > expected.len() + 9 {
                    return Err(io::Error::other("probe response exceeds pinned manifest"));
                }
            }
        });
        recorder.emit(
            "probe_response",
            json!({
                "fetch_id": fetch_id,
                "received_response_bytes": received.len(),
                "request_bytes": query.len(),
                "read_success": read.is_ok(),
                "scope": "separate manifest probe, included in service budgets and whole-run time",
            }),
        );
        read?;
        recorder.measure(&format!("{fetch_id}.probe.validate"), || {
            let valid = received.len() == expected.len() + 9
                && &received[..5] == b"TCS1\0"
                && u32::from_be_bytes(received[5..9].try_into().unwrap()) as usize
                    == expected.len()
                && received[9..] == expected;
            if valid {
                Ok(())
            } else {
                Err(io::Error::other("probe manifest framing/content mismatch"))
            }
        })
    })();
    recorder.close(&format!("{fetch_id}.probe.close"), stream);
    result.map_err(|error| error.to_string())
}

fn output_hash(recorder: &mut Recorder, id: &str, output: &Path) -> io::Result<([u8; 32], u64)> {
    let mut file = recorder.measure(&format!("{id}.output.open"), || File::open(output))?;
    let result = recorder.measure(&format!("{id}.output.independent_sha256"), || {
        let mut hash = Sha256::new();
        let mut bytes = 0_u64;
        let mut buffer = [0; 16 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                return Ok::<_, io::Error>((hash.finalize().into(), bytes));
            }
            hash.update(&buffer[..count]);
            bytes += count as u64;
        }
    });
    recorder.close(&format!("{id}.output.close"), file);
    result
}

fn fetch_report(report: &CellFetchReportV1) -> Value {
    json!({
        "manifest_id": digest_hex(report.manifest_id),
        "payload_sha256": digest_hex(report.payload_sha256),
        "payload_bytes": report.payload_bytes,
        "cached_chunks": report.cached_chunks,
        "downloaded_chunks": report.downloaded_chunks,
        "downloaded_bytes": report.downloaded_bytes,
        "received_response_bytes": report.received_response_bytes,
        "connection_attempts": report.connection_attempts,
        "rejected_responses": report.rejected_responses,
        "supplying_peers": report.supplying_peers.iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
}

#[allow(clippy::too_many_arguments)]
fn observe_fetch(
    recorder: &mut Recorder,
    totals: &mut Totals,
    store: &CellStoreV1,
    address: SocketAddr,
    manifest: &CellManifestV1,
    id: &str,
    cache_state: &str,
    output: &Path,
) -> bool {
    totals.probes_attempted += 1;
    match manifest_probe(recorder, address, manifest, id) {
        Ok(()) => totals.probes_succeeded += 1,
        Err(error) => {
            totals.unexpected_errors += 1;
            recorder.emit("probe_failure", json!({"fetch_id": id, "error": error}));
        }
    }
    totals.fetches_attempted += 1;
    let result = recorder.measure(&format!("{id}.native_fetch_and_publish"), || {
        fetch_cell_to_file(store, manifest.id(), &[address], fetch_limits(), output)
    });
    match result {
        Ok((actual, report)) => {
            totals.successful_fetch_connection_attempts += report.connection_attempts;
            totals.successful_fetch_rejected_responses += report.rejected_responses;
            totals.successful_fetch_received_response_bytes += report.received_response_bytes;
            let actual_hash = output_hash(recorder, id, output);
            let verified = actual == *manifest
                && actual_hash.as_ref().is_ok_and(|(digest, bytes)| {
                    *digest == manifest.payload_sha256() && *bytes == manifest.size()
                });
            let cache_shape_matches = match cache_state {
                "empty_application_cache" => {
                    report.cached_chunks == 0 && report.downloaded_chunks == manifest.chunks().len()
                }
                "complete_application_cache" => {
                    report.cached_chunks == manifest.chunks().len()
                        && report.downloaded_chunks == 0
                        && report.connection_attempts == 0
                        && report.received_response_bytes == 0
                }
                _ => false,
            };
            if verified && cache_shape_matches {
                totals.fetches_succeeded += 1;
                if cache_state == "empty_application_cache" {
                    totals.verified_cold_output_bytes += manifest.size();
                } else {
                    totals.verified_warm_output_bytes += manifest.size();
                }
            } else {
                totals.unexpected_errors += 1;
            }
            recorder.emit(
                "fetch",
                json!({
                    "fetch_id": id,
                    "cache_state": cache_state,
                    "native_success": true,
                    "output_verified": verified,
                    "cache_shape_matches": cache_shape_matches,
                    "output_sha256": actual_hash.as_ref().ok().map(|(digest, _)| digest_hex(*digest)),
                    "output_bytes": actual_hash.as_ref().ok().map(|(_, bytes)| bytes),
                    "output_error": actual_hash.err().map(|error| error.to_string()),
                    "report": fetch_report(&report),
                    "native_connect_wall_ns": null,
                    "native_hash_wall_ns": null,
                    "native_phase_note": "public API exposes inclusive fetch only; no probe timing is substituted",
                }),
            );
            verified && cache_shape_matches
        }
        Err(error) => {
            totals.fetch_errors += 1;
            totals.unexpected_errors += 1;
            totals.failed_fetch_transport_counters_unknown += 1;
            recorder.emit(
                "fetch",
                json!({
                    "fetch_id": id,
                    "cache_state": cache_state,
                    "native_success": false,
                    "error": error.to_string(),
                    "report": null,
                    "unknown_counter_note": "error API supplies no per-fetch attempts/reject/byte report; aggregate server report still includes admitted work",
                }),
            );
            false
        }
    }
}

fn clients(
    recorder: &mut Recorder,
    totals: &mut Totals,
    directory: &Path,
    address: SocketAddr,
    manifest: &CellManifestV1,
) {
    for pair in 0..PAIRS {
        let path = directory.join(format!("consumer-{pair}.sqlite"));
        let opened = recorder.measure(&format!("pair-{pair}.consumer_cache.open"), || {
            CellStoreV1::open(&path, cache_config())
        });
        let store = match opened {
            Ok(store) => store,
            Err(error) => {
                totals.unexpected_errors += 1;
                recorder.emit(
                    "unattempted_fetches",
                    json!({"pair": pair, "count": 2, "error": error.to_string()}),
                );
                continue;
            }
        };
        let cold_success = observe_fetch(
            recorder,
            totals,
            &store,
            address,
            manifest,
            &format!("pair-{pair}.cold"),
            "empty_application_cache",
            &directory.join(format!("output-{pair}-cold.bin")),
        );
        observe_fetch(
            recorder,
            totals,
            &store,
            address,
            manifest,
            &format!("pair-{pair}.warm"),
            if cold_success {
                "complete_application_cache"
            } else {
                "prior_fetch_failed_or_partial"
            },
            &directory.join(format!("output-{pair}-warm.bin")),
        );
        recorder.close(&format!("pair-{pair}.consumer_cache.close"), store);
    }
    let opened = recorder.measure("absent.consumer_cache.open", || {
        CellStoreV1::open(&directory.join("absent.sqlite"), cache_config())
    });
    match opened {
        Ok(store) => {
            totals.fetches_attempted += 1;
            let output = directory.join("absent-output.bin");
            let result = recorder.measure("absent.native_fetch_expected_refusal", || {
                fetch_cell_to_file(&store, [0xfe; 32], &[address], fetch_limits(), &output)
            });
            let expected = matches!(
                &result,
                Err(trnm_data_availability::cell::CellErrorV1::Unavailable)
            ) && !output.exists();
            if result.is_err() {
                totals.fetch_errors += 1;
                totals.failed_fetch_transport_counters_unknown += 1;
            }
            if expected {
                totals.expected_refusals += 1;
            } else {
                totals.unexpected_errors += 1;
            }
            recorder.emit(
                "expected_refusal",
                json!({
                    "fetch_id": "absent",
                    "expected_unavailable": expected,
                    "native_success": result.is_ok(),
                    "error": result.as_ref().err().map(ToString::to_string),
                    "output_exists": output.exists(),
                    "report": result.as_ref().ok().map(|(_, report)| fetch_report(report)),
                    "failed_transport_counters": null,
                }),
            );
            recorder.close("absent.consumer_cache.close", store);
        }
        Err(error) => {
            totals.unexpected_errors += 1;
            recorder.emit(
                "unattempted_fetches",
                json!({"fetch_id": "absent", "count": 1, "error": error.to_string()}),
            );
        }
    }
}

fn workload(
    recorder: &mut Recorder,
    totals: &mut Totals,
    data_root: &Path,
) -> Result<Value, String> {
    let directory = recorder
        .measure("setup.scratch_directory", || {
            tempfile::tempdir_in(data_root)
        })
        .map_err(|error| error.to_string())?;
    let input = directory.path().join("source.weights");
    let mut state = 0x1e67_4a29_0fcd_5b83_u64;
    let payload = recorder.measure("setup.source_generate", || {
        let bytes: Vec<u8> = (0..PAYLOAD_BYTES)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        Ok::<_, String>(bytes)
    })?;
    let expected: [u8; 32] = recorder.measure("setup.source_sha256", || {
        Ok::<_, String>(Sha256::digest(&payload).into())
    })?;
    let mut file = recorder
        .measure("setup.source_file.open", || File::create(&input))
        .map_err(|error| error.to_string())?;
    let written = recorder.measure("setup.source_file.write_and_sync", || {
        file.write_all(&payload)?;
        file.sync_all()
    });
    recorder.close("setup.source_file.close", file);
    recorder.close("setup.source_buffer.drop", payload);
    written.map_err(|error| error.to_string())?;
    let source = directory.path().join("source.sqlite");
    let store = recorder
        .measure("setup.source_cache.open", || {
            CellStoreV1::open(&source, cache_config())
        })
        .map_err(|error| error.to_string())?;
    let packed = recorder.measure("setup.source_pack_hash_and_persist", || {
        store.pack_file(
            &input,
            CellContextV1 {
                family: "cell-serving-observer-v1".into(),
                base: [1; 32],
                parent: [2; 32],
                tokenizer: [3; 32],
                layout: [4; 32],
                runtime: [5; 32],
            },
            CHUNK_BYTES,
        )
    });
    recorder.close("setup.source_cache.close", store);
    let manifest = packed.map_err(|error| error.to_string())?;
    if manifest.payload_sha256() != expected || manifest.size() != PAYLOAD_BYTES as u64 {
        return Err("packed source does not match generated fixture".into());
    }
    recorder.emit(
        "fixture",
        json!({
            "payload_sha256": digest_hex(expected),
            "payload_bytes": PAYLOAD_BYTES,
            "manifest_id": digest_hex(manifest.id()),
            "manifest_bytes": manifest.encode().len(),
            "chunks": manifest.chunks().len(),
            "chunk_bytes": CHUNK_BYTES,
        }),
    );
    let listener = recorder
        .measure("setup.listener.bind", || TcpListener::bind("127.0.0.1:0"))
        .map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let service = recorder
        .measure("setup.service.spawn", || {
            RunningService::start(listener, source)
        })
        .map_err(|error| error.to_string())?;
    let client_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        clients(recorder, totals, directory.path(), address, &manifest);
    }));
    let service_report = service.finish(recorder);
    recorder.emit(
        "service",
        json!({
            "success": service_report.is_ok(),
            "report": service_report.as_ref().ok(),
            "error": service_report.as_ref().err(),
        }),
    );
    let mut file_sizes = Vec::new();
    let disk_sample = recorder.measure("teardown.retained_file_sizes", || -> io::Result<()> {
        for entry in fs::read_dir(directory.path())? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            file_sizes.push(
                json!({"name": entry.file_name().to_string_lossy(), "bytes": metadata.len()}),
            );
        }
        Ok(())
    });
    if disk_sample.is_err() {
        totals.unexpected_errors += 1;
    }
    recorder.emit(
        "disk_sample",
        json!({
            "files": file_sizes,
            "scope": "post-drain file lengths, not physical allocation or WAL/disk peak",
            "error": disk_sample.err().map(|error| error.to_string()),
        }),
    );
    let cleanup = recorder.measure("teardown.scratch_cleanup", || directory.close());
    if client_result.is_err() {
        return Err(
            "client observation panicked; service joined and scratch cleanup attempted".into(),
        );
    }
    cleanup.map_err(|error| error.to_string())?;
    service_report
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: cell_serving_ab_observer DATA_ROOT RUN_ID");
        std::process::exit(2);
    }
    let mut recorder = Recorder {
        origin: Instant::now(),
        run_id: args[2].clone(),
        sequence: 0,
        write_error: None,
    };
    recorder.emit("configuration", json!({
        "observer_sha256": digest_hex(Sha256::digest(OBSERVER_SOURCE).into()),
        "payload_bytes": PAYLOAD_BYTES,
        "chunk_bytes": CHUNK_BYTES,
        "cold_warm_pairs": PAIRS,
        "planned_native_fetches": 2 * PAIRS + 1,
        "planned_successful_fetches": 2 * PAIRS,
        "planned_expected_refusals": 1,
        "planned_manifest_probes": 2 * PAIRS,
        "client": {"request_timeout_ms": 1000, "overall_timeout_ms": 5000, "parallelism": 2,
            "max_connections": fetch_limits().max_connections, "max_response_bytes": fetch_limits().max_response_bytes},
        "service": {"request_timeout_ms": 1000, "overall_timeout_ms": 30000, "max_workers": 4,
            "max_connections": serving_limits().max_connections, "max_response_bytes": serving_limits().max_response_bytes},
        "cache": {"max_database_bytes": cache_config().max_database_bytes,
            "max_logical_bytes": cache_config().max_logical_bytes, "max_chunk_rows": 128, "max_manifest_rows": 16},
        "cache_scope": "fresh application caches and fresh process per trial; OS/device caches uncontrolled, source pages warmed by fixture creation",
        "denominator_scope": "source setup, probe, all native fetch attempts, independent output verification, closes, full service drain and scratch cleanup; JSON observation overhead included",
        "exclusions": "compilation and coordinator metadata collection are outside this executable; no WAN, release closure, Hepta load/install/inference or ledger throughput is measured",
        "internal_phase_scope": "native fetch includes actual connects, retries, chunk/full hashes, cache commit, file sync and publication; public API does not split their wall times",
    }));
    let mut totals = Totals::default();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        workload(&mut recorder, &mut totals, Path::new(&args[1]))
    }))
    .unwrap_or_else(|_| Err("observer panicked".into()));
    if result.is_err() {
        totals.unexpected_errors += 1;
    }
    let success = result.is_ok()
        && totals.unexpected_errors == 0
        && totals.fetches_attempted == (2 * PAIRS + 1) as u64
        && totals.fetches_succeeded == (2 * PAIRS) as u64
        && totals.expected_refusals == 1
        && totals.probes_succeeded == (2 * PAIRS) as u64
        && recorder.write_error.is_none();
    let whole_run_ns = recorder.origin.elapsed().as_nanos();
    recorder.emit("summary", json!({
        "success": success,
        "whole_run_wall_ns": whole_run_ns,
        "totals": totals,
        "service": result.as_ref().ok(),
        "error": result.as_ref().err(),
        "observation_write_error": recorder.write_error,
        "process_status": fs::read_to_string("/proc/self/status").ok(),
        "process_status_scope": "Linux process-wide status near exit; VmHWM includes all threads and observer setup, unavailable elsewhere",
        "whole_run_scope": "inclusive through cleanup, before final summary serialization and process exit; coordinator records complete subprocess wall time separately",
    }));
    if !success || recorder.write_error.is_some() {
        std::process::exit(1);
    }
}
