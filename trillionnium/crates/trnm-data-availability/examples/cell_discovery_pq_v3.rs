//! Finite, same-host loopback development example for native PQ discovery v3.
//!
//! Run with one directory that does not exist yet:
//! cargo run -p trnm-data-availability --example cell_discovery_pq_v3 -- /tmp/new-pq-v3-run
//!
//! Known fixture seeds authorize only this isolated demonstration. Do not use
//! these keys for a real authority roster. A signed announcement is followed by
//! authenticated discovery, a genuinely cold payload fetch, an actual output
//! byte comparison, withdrawal, and a counted refusal despite the populated
//! cache. Every phase receives the same original absolute deadline. Discovery
//! and payload share one connection/response-byte allowance within the fetch;
//! announcements and the withdrawal control are separate, explicitly counted
//! operations. No model loader, Hepta integration, public-WAN deployment,
//! independent operator, custody, payment or FinalUse claim is made.

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("cell_discovery_pq_v3 requires Unix directory identity and OS entropy support");
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    native::main()
}

#[cfg(unix)]
mod native {
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::{
        error::Error,
        fs::{self, OpenOptions},
        io::{self, Write},
        net::{SocketAddr, TcpListener},
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, JoinHandle},
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
    use trnm_data_availability::cell::{
        digest_hex,
        discovery::{
            cell_discovery_context_digest,
            pq3::{
                announce_cell_provider_pq_v3, fetch_discovered_cell_to_file_pq_v3,
                serve_cell_rendezvous_pq_v3, CellBootstrapPinV3, CellBootstrapSignerV3,
                CellDiscoveryFailureV3, CellDiscoveryObservationV3, CellDiscoveryOptionsV3,
                CellProviderDirectoryV3, CellProviderRecordV3, CellProviderStatementV3,
                CellRendezvousLimitsV3, CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3,
            },
            CellDiscoveryAddressPolicyV1, CellDiscoveryContextV1, CellDiscoveryRequestV1,
        },
        pq::{CellPqKeyPinV2, CellPqKeyPinsV2},
        serve_cells, CellCacheConfigV4, CellContextV1, CellErrorV1, CellPeerLimitsV1, CellResultV1,
        CellStoreV1,
    };
    use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
    use zeroize::Zeroizing;

    const OPERATION_WINDOW: Duration = Duration::from_secs(10);
    const PAYLOAD_BYTES: usize = 40 * 1024;
    const SOURCE: &[u8] = include_bytes!("cell_discovery_pq_v3.rs");

    fn require(condition: bool, reason: &'static str) -> CellResultV1<()> {
        if condition {
            Ok(())
        } else {
            Err(CellErrorV1::Invalid(reason))
        }
    }

    fn now() -> CellResultV1<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.as_secs())
            .map_err(|_| CellErrorV1::Invalid("example wall clock"))
    }

    fn cache() -> CellCacheConfigV4 {
        CellCacheConfigV4 {
            max_database_bytes: 4 * 1024 * 1024,
            max_logical_bytes: 2 * 1024 * 1024,
            max_chunk_rows: 64,
            max_manifest_rows: 16,
        }
    }

    fn limits() -> CellPeerLimitsV1 {
        CellPeerLimitsV1 {
            request_timeout: Duration::from_secs(2),
            overall_timeout: OPERATION_WINDOW,
            max_cell_bytes: PAYLOAD_BYTES as u64,
            parallelism: 1,
            max_connections: 16,
            max_response_bytes: 256 * 1024,
        }
    }

    fn cell_context() -> CellContextV1 {
        CellContextV1 {
            family: "cell-discovery-pq-v3-loopback-example".into(),
            base: [21; 32],
            parent: [22; 32],
            tokenizer: [23; 32],
            layout: [24; 32],
            runtime: [25; 32],
        }
    }

    fn fixture_key(seed: u8, clock: u64) -> CellResultV1<(PqNativeSigningKey, CellPqKeyPinV2)> {
        let seed = Zeroizing::new([seed; 32]);
        let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
        let key_id = ml_dsa_65_key_id_from_spki(&spki)
            .map_err(|_| CellErrorV1::Invalid("example public key"))?;
        let key = PqNativeSigningKey::from_owned_seed(seed, key_id)
            .map_err(|_| CellErrorV1::Invalid("example native signing key"))?;
        Ok((
            key,
            CellPqKeyPinV2 {
                key_id,
                generation: 1,
                spki,
                not_before: clock.saturating_sub(1),
                expires_at: clock
                    .checked_add(300)
                    .ok_or(CellErrorV1::Invalid("example authority expiry"))?,
                revoked_at: None,
            },
        ))
    }

    fn advertisement(
        request: CellDiscoveryRequestV1,
        endpoint: SocketAddr,
        key: &PqNativeSigningKey,
        sequence: u64,
        withdrawn: bool,
    ) -> CellResultV1<CellProviderRecordV3> {
        let clock = now()?;
        let lease_epoch = clock / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3;
        let expires = lease_epoch
            .checked_add(1)
            .and_then(|next| next.checked_mul(CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3))
            .ok_or(CellErrorV1::Invalid("example lease epoch"))?;
        CellProviderRecordV3::sign(
            CellProviderStatementV3 {
                request,
                owner: key.public_key_id(),
                owner_generation: 1,
                endpoint,
                sequence,
                lease_epoch,
                issued_unix_seconds: clock,
                expires_unix_seconds: expires,
                withdrawn,
            },
            key,
        )
    }

    fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    struct Worker<T> {
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<CellResultV1<T>>>,
    }

    impl<T: Send + 'static> Worker<T> {
        fn start(
            name: &str,
            operation: impl FnOnce(Arc<AtomicBool>) -> CellResultV1<T> + Send + 'static,
        ) -> CellResultV1<Self> {
            let stop = Arc::new(AtomicBool::new(false));
            let shutdown = Arc::clone(&stop);
            let handle = thread::Builder::new()
                .name(name.into())
                .spawn(move || operation(shutdown))?;
            Ok(Self {
                stop,
                handle: Some(handle),
            })
        }

        fn finish(mut self) -> CellResultV1<T> {
            self.stop.store(true, Ordering::Release);
            self.handle
                .take()
                .ok_or(CellErrorV1::Invalid("example worker already joined"))?
                .join()
                .map_err(|_| CellErrorV1::Invalid("example worker panicked"))?
        }
    }

    impl<T> Drop for Worker<T> {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn observation(value: &CellDiscoveryObservationV3) -> Value {
        json!({
            "connection_attempts": value.connection_attempts,
            "received_response_bytes": value.received_response_bytes,
            "bootstrap_validation_attempts": value.bootstrap_validation_attempts,
            "authenticated_bootstrap_responses": value.authenticated_bootstrap_responses,
            "record_validation_attempts": value.record_validation_attempts,
            "rejected_records": value.rejected_records,
            "capacity_rejections": value.capacity_rejections,
            "rejected_bootstraps": value.rejected_bootstraps,
        })
    }

    fn refused(
        stage: &str,
        failure: &CellDiscoveryFailureV3,
        expected: bool,
        deadline: Instant,
    ) -> Value {
        json!({
            "scope": "client_operation",
            "stage": stage,
            "result": "refused",
            "expected": expected,
            "cause": failure.to_string(),
            "original_deadline_remaining_micros": deadline.saturating_duration_since(Instant::now()).as_micros(),
            "total_connection_attempts": failure.total_connection_attempts,
            "total_received_response_bytes": failure.total_received_response_bytes,
            "discovery": observation(&failure.discovery),
        })
    }

    fn announce(
        stage: &str,
        record: &CellProviderRecordV3,
        keys: &CellPqKeyPinsV2,
        options: &CellDiscoveryOptionsV3,
        deadline: Instant,
        journal: &mut Vec<Value>,
    ) -> CellResultV1<()> {
        match announce_cell_provider_pq_v3(record, 0, keys, options, limits(), deadline) {
            Ok(observed) => {
                journal.push(json!({
                    "scope": "client_operation",
                    "stage": stage,
                    "result": "accepted",
                    "original_deadline_remaining_micros": deadline.saturating_duration_since(Instant::now()).as_micros(),
                    "total_connection_attempts": observed.connection_attempts,
                    "total_received_response_bytes": observed.received_response_bytes,
                    "discovery": observation(&observed),
                }));
                Ok(())
            }
            Err(failure) => {
                journal.push(refused(stage, &failure, false, deadline));
                Err(failure.cause)
            }
        }
    }

    fn run(root: &Path, journal: &mut Vec<Value>) -> CellResultV1<Value> {
        let context = CellDiscoveryContextV1 {
            namespace: [11; 32],
            network: [12; 32],
            parameters: [13; 32],
            genesis: [14; 32],
        };
        let source_path = root.join("source.bin");
        let source: Vec<_> = (0..PAYLOAD_BYTES)
            .map(|index| ((index ^ (index >> 8)) % 251) as u8)
            .collect();
        write_new(&source_path, &source)?;
        let origin_path = root.join("origin-cache");
        let origin = CellStoreV1::open(&origin_path, cache())?;
        let manifest = origin.pack_file(&source_path, cell_context(), 16_384)?;
        drop(origin);
        let request = CellDiscoveryRequestV1 {
            context,
            cell_context: cell_discovery_context_digest(&cell_context())?,
            manifest: manifest.id(),
        };
        let clock = now()?;
        let (provider_key, provider_pin) = fixture_key(41, clock)?;
        let provider_keys = CellPqKeyPinsV2::new(vec![provider_pin])?;
        let (bootstrap_key, bootstrap_authority) = fixture_key(91, clock)?;
        let bootstrap_keys = CellPqKeyPinsV2::new(vec![bootstrap_authority.clone()])?;
        write_new(&root.join("provider-pins.cpk2"), &provider_keys.encode())?;
        write_new(&root.join("bootstrap-pins.cpk2"), &bootstrap_keys.encode())?;
        let data_listener = TcpListener::bind("127.0.0.1:0")?;
        let data_endpoint = data_listener.local_addr()?;
        let bootstrap_listener = TcpListener::bind("127.0.0.1:0")?;
        let bootstrap = CellBootstrapPinV3 {
            endpoint: bootstrap_listener.local_addr()?,
            key_id: bootstrap_authority.key_id,
            generation: bootstrap_authority.generation,
        };
        let signer = CellBootstrapSignerV3::new(bootstrap, bootstrap_key, bootstrap_keys.clone())?;
        let mut ports = vec![data_endpoint.port(), bootstrap.endpoint.port()];
        ports.sort_unstable();
        ports.dedup();
        let options = CellDiscoveryOptionsV3 {
            request,
            bootstraps: vec![bootstrap],
            bootstrap_keys,
            addresses: CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports },
        };
        let server_directory = CellProviderDirectoryV3::open(
            &root.join("bootstrap-directory.sqlite"),
            context,
            provider_keys.clone(),
        )?;
        let client_directory = CellProviderDirectoryV3::open(
            &root.join("client-directory.sqlite"),
            context,
            provider_keys.clone(),
        )?;
        let client = CellStoreV1::open(&root.join("cold-client-cache"), cache())?;
        let address_policy = options.addresses.clone();
        let data_worker = Worker::start("pq-v3-example-payload", move |stop| {
            let store = CellStoreV1::open(&origin_path, cache())?;
            serve_cells(
                &data_listener,
                &store,
                &stop,
                CellPeerLimitsV1 {
                    overall_timeout: Duration::from_secs(30),
                    ..limits()
                },
            )
        })?;
        let bootstrap_worker = Worker::start("pq-v3-example-bootstrap", move |stop| {
            serve_cell_rendezvous_pq_v3(
                &bootstrap_listener,
                &server_directory,
                &signer,
                &address_policy,
                &stop,
                CellRendezvousLimitsV3 {
                    request_timeout: Duration::from_secs(2),
                    lifetime: Duration::from_secs(30),
                    max_connections: 16,
                },
            )
        })?;
        // Captured once, before the first signature/announcement in the session.
        // No later phase is allowed to obtain a replacement deadline.
        let original_deadline = Instant::now() + OPERATION_WINDOW;
        let operation_result = (|| -> CellResultV1<Value> {
            let advert = advertisement(request, data_endpoint, &provider_key, 1, false)?;
            write_new(&root.join("advertisement.cdp3"), &advert.encode())?;
            announce(
                "announce",
                &advert,
                &provider_keys,
                &options,
                original_deadline,
                journal,
            )?;
            let output = root.join("fetched.bin");
            let (_, report) = match fetch_discovered_cell_to_file_pq_v3(
                &client,
                &client_directory,
                &options,
                limits(),
                original_deadline,
                &output,
            ) {
                Ok(value) => value,
                Err(failure) => {
                    journal.push(refused("cold_fetch", &failure, false, original_deadline));
                    return Err(failure.cause);
                }
            };
            journal.push(json!({
                "scope": "client_operation",
                "stage": "cold_fetch",
                "result": "accepted",
                "original_deadline_remaining_micros": original_deadline.saturating_duration_since(Instant::now()).as_micros(),
                "total_connection_attempts": report.fetch.connection_attempts,
                "total_received_response_bytes": report.fetch.received_response_bytes,
                "discovery": observation(&report.discovery),
                "manifest_initial_cache_hit": report.manifest_initial_cache_hit,
                "cached_chunks": report.fetch.cached_chunks,
                "downloaded_chunks": report.fetch.downloaded_chunks,
                "downloaded_bytes": report.fetch.downloaded_bytes,
                "rejected_payload_responses": report.fetch.rejected_responses,
                "selected_providers": report.discovered_providers,
                "supplying_peers": report.fetch.supplying_peers,
            }));
            require(
                !report.manifest_initial_cache_hit && report.fetch.cached_chunks == 0,
                "example must perform a cold fetch",
            )?;
            require(
                report.fetch.connection_attempts > report.discovery.connection_attempts
                    && report.fetch.received_response_bytes
                        > report.discovery.received_response_bytes,
                "example shared payload accounting",
            )?;
            require(
                report.fetch.connection_attempts <= limits().max_connections
                    && report.fetch.received_response_bytes <= limits().max_response_bytes,
                "example original fetch budgets",
            )?;
            let loaded = fs::read(&output)?;
            let loaded_sha256: [u8; 32] = Sha256::digest(&loaded).into();
            require(
                loaded == source && loaded_sha256 == manifest.payload_sha256(),
                "example actual output byte verification",
            )?;
            let withdrawal = advertisement(request, data_endpoint, &provider_key, 2, true)?;
            write_new(&root.join("withdrawal.cdp3"), &withdrawal.encode())?;
            announce(
                "withdraw",
                &withdrawal,
                &provider_keys,
                &options,
                original_deadline,
                journal,
            )?;
            let forbidden_output = root.join("withdrawn-fetch.bin");
            match fetch_discovered_cell_to_file_pq_v3(
                &client,
                &client_directory,
                &options,
                limits(),
                original_deadline,
                &forbidden_output,
            ) {
                Err(failure) => {
                    let expected = matches!(
                        failure.cause,
                        CellErrorV1::Invalid("discovery has no admissible provider")
                    );
                    journal.push(refused(
                        "fetch_after_withdrawal",
                        &failure,
                        expected,
                        original_deadline,
                    ));
                    require(
                        expected,
                        "example withdrawal control failed for an unrelated reason",
                    )?;
                    require(
                        failure.total_connection_attempts > 0
                            && failure
                                .total_received_response_bytes
                                .is_some_and(|bytes| bytes > 0),
                        "example failed operation denominator",
                    )?;
                }
                Ok((_, report)) => {
                    journal.push(json!({
                        "scope": "client_operation", "stage": "fetch_after_withdrawal",
                        "result": "unexpected_acceptance",
                        "total_connection_attempts": report.fetch.connection_attempts,
                        "total_received_response_bytes": report.fetch.received_response_bytes,
                        "discovery": observation(&report.discovery),
                    }));
                    return Err(CellErrorV1::Invalid(
                        "withdrawn provider manufactured an eligible source",
                    ));
                }
            }
            require(
                !forbidden_output.exists(),
                "example withdrawal output must not exist",
            )?;
            require(
                Instant::now() < original_deadline,
                "example original deadline expired",
            )?;
            Ok(json!({
                "manifest": digest_hex(manifest.id()),
                "payload_sha256": digest_hex(loaded_sha256),
                "actual_output_bytes_checked": loaded.len(),
                "bootstrap_endpoint": bootstrap.endpoint,
                "bootstrap_key_id": digest_hex(bootstrap.key_id),
                "payload_endpoint": data_endpoint,
                "withdrawn_fetch_created_output": false,
            }))
        })();
        // Finish both finite servers even when a counted client operation fails.
        let data_result = data_worker.finish();
        let bootstrap_result = bootstrap_worker.finish();
        journal.push(match &data_result {
            Ok(connections) => json!({"scope": "payload_server", "connections": connections}),
            Err(error) => json!({"scope": "payload_server", "error": error.to_string()}),
        });
        journal.push(match &bootstrap_result {
            Ok(served) => json!({
                "scope": "bootstrap_server", "connections": served.connections,
                "rejected_requests": served.rejected_requests,
                "record_validation_attempts": served.record_validation_attempts,
                "response_signing_attempts": served.response_signing_attempts,
                "charged_native_primitive_slots": served.record_validation_attempts
                    + 2 * served.response_signing_attempts,
                "native_primitive_slot_limit": 64,
            }),
            Err(error) => json!({"scope": "bootstrap_server", "error": error.to_string()}),
        });
        let result = operation_result?;
        data_result?;
        let served = bootstrap_result?;
        require(
            served.record_validation_attempts + 2 * served.response_signing_attempts <= 64,
            "example server native primitive slots",
        )?;
        Ok(result)
    }

    pub fn main() -> Result<(), Box<dyn Error>> {
        let mut args = std::env::args_os().skip(1);
        let target = args
            .next()
            .ok_or("usage: cell_discovery_pq_v3 <new-output-directory>")?;
        if target == "--help" || target == "-h" {
            println!("usage: cell_discovery_pq_v3 <new-output-directory>\nCreates a new same-host loopback native PQ fixture; refuses an existing directory.");
            return Ok(());
        }
        if args.next().is_some() {
            return Err("usage: cell_discovery_pq_v3 <new-output-directory>".into());
        }
        let root = PathBuf::from(target);
        fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let started = Instant::now();
        let mut journal = Vec::new();
        let result = run(&root, &mut journal);
        let operations: Vec<_> = journal
            .iter()
            .filter(|entry| entry["scope"] == "client_operation")
            .collect();
        let attempts: u64 = operations
            .iter()
            .filter_map(|entry| entry["total_connection_attempts"].as_u64())
            .sum();
        let received: Option<u64> = operations.iter().try_fold(0_u64, |total, entry| {
            entry["total_received_response_bytes"]
                .as_u64()
                .and_then(|bytes| total.checked_add(bytes))
        });
        let report = json!({
            "profile": "cell-provider-discovery-pq-v3",
            "status": if result.is_ok() { "passed" } else { "failed" },
            "scope": "temporary_same_host_loopback_development",
            "source_sha256": digest_hex(Sha256::digest(SOURCE).into()),
            "fixed_fixture_keys_are_public_test_material": true,
            "independent_operators_demonstrated": false,
            "public_wan_or_hepta_loader_exercised": false,
            "output_directory": root,
            "original_operation_window_milliseconds": OPERATION_WINDOW.as_millis(),
            "per_operation_connection_limit": limits().max_connections,
            "per_operation_response_byte_limit": limits().max_response_bytes,
            "response_byte_scope": "application responses actually read; excludes requests and transport overhead",
            "elapsed_micros_including_preparation_and_shutdown": started.elapsed().as_micros(),
            "client_operations_including_expected_refusal": operations.len(),
            "total_connection_attempts_including_failures": attempts,
            "total_received_response_bytes_including_failures": received,
            "result": result.as_ref().ok(),
            "error": result.as_ref().err().map(ToString::to_string),
            "observations": journal,
        });
        let mut bytes = serde_json::to_vec_pretty(&report)?;
        bytes.push(b'\n');
        write_new(&root.join("report.json"), &bytes)?;
        print!("{}", String::from_utf8(bytes)?);
        result?;
        Ok(())
    }
}
