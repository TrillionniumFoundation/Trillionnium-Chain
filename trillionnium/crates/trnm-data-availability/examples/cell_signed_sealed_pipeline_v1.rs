//! Native component pipeline: CPV4/TCV2, real explicit TCP BEP52, complete
//! consumer CAS readback, both sealed closures, then strict safetensors reading.
//!
//! The tensor and environment JSON are synthetic fixtures. The fixed public
//! fixture signing seed is unsuitable for deployment. Owner pins are provisioned
//! before listening and never learned from the peer. This does not start Hepta,
//! execute a model, inventory this executable's libraries, or grant FinalUse.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err("this observation requires real Linux memfd seals".into())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        error::Error,
        fs, io,
        net::TcpListener,
        os::fd::AsFd,
        path::Path,
        sync::atomic::{AtomicBool, Ordering},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use rustix::fs::{fcntl_get_seals, SealFlags};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
    use trnm_data_availability::cell::{
        fetch_cell_bep52_with_content,
        pq::{
            CellPqContentAuthorizationV4, CellPqContentExpectationV4, CellPqContentStatementV4,
            CellPqKeyPinV2, CellPqReleaseExpectationV2,
        },
        CellBep52BindingV1, CellBep52PeerLimitsV1, CellBep52PeerSessionV1, CellBep52PeerUsageV1,
        CellBep52SeedV1, CellCacheConfigV4, CellClosureFileV1, CellContentReadSessionV2,
        CellContextV1, CellErrorV1, CellFileRoleV1, CellLoaderContextV1, CellManifestV1,
        CellModelReleaseRootV1, CellReleaseClosureV1, CellReleaseLimitsV1, CellResidencyConfigV1,
        CellResidencyV1, CellSealedLoaderBundleV1, CellSealedLoaderLimitsV1, CellStoreV1,
        CellTensorContractV1, CellTensorDTypeV1, CellTensorFileV1, CellTensorSpecV1,
        CellVersionContentV2, CellVersionLoaderContextV1, CellVersionManifestV1,
        PinnedCellVersionContentV2, CELL_BEP52_PEER_PROFILE_V1, CELL_BEP52_PIECE_BYTES_V1,
    };
    use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
    use zeroize::Zeroizing;

    type ObservationResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
    const ELEMENTS: u64 = 8193;
    const MODEL_PATH: &str = "base/model.safetensors";
    const ENVIRONMENT_PATH: &str = "runtime/config.json";
    const PAYLOAD_LIMIT: u64 = 1_048_576;

    fn check(value: bool, reason: &'static str) -> ObservationResult<()> {
        if value {
            Ok(())
        } else {
            Err(CellErrorV1::Invalid(reason).into())
        }
    }

    fn config() -> CellCacheConfigV4 {
        CellCacheConfigV4 {
            max_database_bytes: 8 << 20,
            max_logical_bytes: PAYLOAD_LIMIT,
            max_chunk_rows: 64,
            max_manifest_rows: 8,
        }
    }

    fn context(runtime: [u8; 32]) -> CellContextV1 {
        CellContextV1 {
            family: "signed-sealed-component-pipeline-v1".into(),
            base: [1; 32],
            parent: [2; 32],
            tokenizer: [3; 32],
            layout: [4; 32],
            runtime,
        }
    }

    fn declaration(
        path: &str,
        role: CellFileRoleV1,
        manifest: &CellManifestV1,
    ) -> CellClosureFileV1 {
        CellClosureFileV1 {
            path: path.into(),
            role,
            manifest: manifest.id(),
            payload_sha256: manifest.payload_sha256(),
            payload_bytes: manifest.size(),
            dependencies: vec![],
        }
    }

    fn owner(closure: &CellReleaseClosureV1, role: CellFileRoleV1) -> CellLoaderContextV1 {
        CellLoaderContextV1 {
            closure_id: closure.id(),
            context: closure.release().context().clone(),
            selected_generation: closure.selected_generation(),
            loader_profile: closure.loader_profile(),
            required_roles: vec![role],
            max_payload_bytes: PAYLOAD_LIMIT,
            max_chunks: 64,
        }
    }

    fn content_session(deadline: Instant) -> ObservationResult<CellContentReadSessionV2> {
        Ok(CellContentReadSessionV2::new(
            CellReleaseLimitsV1 {
                max_payload_bytes: PAYLOAD_LIMIT,
                max_chunks: 64,
                deadline,
            },
            1,
        )?)
    }

    fn peer_session(
        operation: [u8; 32],
        deadline: Instant,
        connections: u64,
    ) -> ObservationResult<CellBep52PeerSessionV1> {
        Ok(CellBep52PeerSessionV1::new(
            operation,
            CellBep52PeerLimitsV1 {
                deadline,
                request_timeout: Duration::from_secs(2),
                max_connections: connections,
                max_received_bytes: PAYLOAD_LIMIT,
                max_sent_bytes: PAYLOAD_LIMIT,
                max_messages: 128,
            },
        )?)
    }

    fn wire_usage(usage: &CellBep52PeerUsageV1) -> Value {
        json!({
            "connection_attempts": usage.connection_attempts,
            "received_bytes": usage.received_bytes,
            "sent_bytes": usage.sent_bytes,
            "received_messages": usage.received_messages,
            "sent_messages": usage.sent_messages,
            "refused_connections": usage.refused_connections,
            "completed_fetches": usage.completed_fetches,
        })
    }

    // A real native seed, with no handcrafted peer messages or mock transport.
    // Its accept poll and its socket work share the caller's original deadline;
    // any client failure cancels and joins this finite worker before returning.
    fn transfer(
        source: &Path,
        consumer: &CellStoreV1,
        binding: &CellBep52BindingV1,
        content: &PinnedCellVersionContentV2<'_>,
        client: &mut CellBep52PeerSessionV1,
        deadline: Instant,
        evidence: &mut Value,
    ) -> ObservationResult<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let source = source.to_owned();
        let server_binding = binding.clone();
        let mut server_session = peer_session(binding.manifest_id(), deadline, 1)?;
        let cancelled = server_session.cancellation_handle();
        let accept_cancelled = cancelled.clone();
        let server = thread::spawn(move || {
            let result = (|| -> ObservationResult<()> {
                let store = CellStoreV1::open_read_only(&source)?;
                let seed = CellBep52SeedV1::prepare(&store, &server_binding, deadline)?;
                let stream = loop {
                    check(
                        !accept_cancelled.load(Ordering::Acquire) && Instant::now() < deadline,
                        "pipeline original accept deadline or cancellation",
                    )?;
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => return Err(error.into()),
                    }
                };
                seed.serve_connection(stream, *b"-CP0001-seed-peer001", &mut server_session)?;
                Ok(())
            })();
            // Failed service still consumes the same original reservation.
            (result, server_session.usage().clone())
        });
        let fetched = fetch_cell_bep52_with_content(
            consumer,
            binding,
            content,
            &[address],
            *b"-CP0001-read-peer001",
            client,
        );
        if !matches!(&fetched, Ok(report) if report.supplying_peers.contains(&address)) {
            // Also release the listener if a future fixture accidentally hits
            // only cached chunks and fetch succeeds without dialing this seed.
            cancelled.store(true, Ordering::Release);
        }
        let (served, seed_usage) = match server.join() {
            Ok((result, usage)) => (result, Some(usage)),
            Err(_) => (Err("native seed worker panicked".into()), None),
        };
        let mut row = json!({
            "endpoint": address.to_string(),
            "manifest_id": hex::encode(binding.manifest_id()),
            "full_infohash": hex::encode(binding.info_hash()),
            "metadata_info_bytes": binding.info_bytes().len(),
            "client_cumulative_usage": wire_usage(client.usage()),
            "seed_usage": seed_usage.as_ref().map(wire_usage),
            "client_error": fetched.as_ref().err().map(ToString::to_string),
            "server_error": served.as_ref().err().map(ToString::to_string),
        });
        if let Ok(report) = &fetched {
            row["cached_chunks"] = json!(report.cached_chunks);
            row["downloaded_chunks"] = json!(report.downloaded_chunks);
            row["downloaded_bytes"] = json!(report.downloaded_bytes);
            row["payload_bytes"] = json!(report.payload_bytes);
            row["supplying_peers"] = json!(report
                .supplying_peers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>());
        }
        evidence["network"]["fetches"]
            .as_array_mut()
            .ok_or("pipeline network evidence shape")?
            .push(row);
        let report = fetched?;
        served?;
        check(
            report.cached_chunks == 0
                && report.downloaded_bytes == report.payload_bytes
                && report.supplying_peers.contains(&address),
            "pipeline requires an actual complete fresh TCP transfer",
        )
    }

    fn sealed_observation(bundle: &CellSealedLoaderBundleV1<'_>) -> ObservationResult<Value> {
        let mut files = Vec::new();
        for declaration in bundle.closure().files() {
            let file = bundle.file(&declaration.path, declaration.role)?;
            let seals = fcntl_get_seals(file.as_fd())?;
            check(
                seals.contains(
                    SealFlags::SEAL
                        | SealFlags::SHRINK
                        | SealFlags::GROW
                        | SealFlags::WRITE
                        | SealFlags::EXEC,
                ),
                "pipeline actual kernel seals",
            )?;
            files.push(json!({
                "path": file.path(),
                "manifest_id": hex::encode(file.manifest_id()),
                "payload_bytes": file.payload_bytes(),
                "actual_post_seal_payload_sha512": hex::encode(file.payload_sha512()),
                "kernel_seal_bits": seals.bits(),
            }));
        }
        Ok(json!({
            "closure_id": hex::encode(bundle.closure_id()),
            "snapshot_bytes": bundle.snapshot_bytes(),
            "files": files,
        }))
    }

    fn observe(evidence: &mut Value) -> ObservationResult<()> {
        // All phases below receive this same absolute operation deadline.
        let deadline = Instant::now() + Duration::from_secs(30);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let directory = tempfile::tempdir()?;
        let source_path = directory.path().join("publisher.sqlite");
        let source = CellStoreV1::open(&source_path, config())?;
        let consumer = CellStoreV1::open(&directory.path().join("consumer.sqlite"), config())?;
        let empty = consumer.cache_usage()?;
        check(
            empty.chunk_rows == 0 && empty.manifest_rows == 0,
            "pipeline consumer must begin empty",
        )?;
        evidence["started_at_unix_seconds"] = json!(timestamp);

        evidence["stage"] = json!("actual publisher fixture packing");
        let environment_json = json!({
            "fixture": "native-component-pipeline",
            "tensor_dtype": "F32",
            "tensor_elements": ELEMENTS,
        });
        let environment_input = directory.path().join("config.json");
        fs::write(&environment_input, serde_json::to_vec(&environment_json)?)?;
        let environment_manifest = source.pack_file(
            &environment_input,
            context([5; 32]),
            CELL_BEP52_PIECE_BYTES_V1,
        )?;
        let environment = CellReleaseClosureV1::new(
            context([5; 32]),
            1,
            [6; 32],
            vec![0],
            vec![declaration(
                ENVIRONMENT_PATH,
                CellFileRoleV1::Configuration,
                &environment_manifest,
            )],
        )?;
        let header = format!(
            r#"{{"weights":{{"dtype":"F32","shape":[{ELEMENTS}],"data_offsets":[0,{}]}}}}"#,
            ELEMENTS * 4
        );
        let mut tensor_bytes = (header.len() as u64).to_le_bytes().to_vec();
        tensor_bytes.extend(header.as_bytes());
        tensor_bytes.extend((0..ELEMENTS).flat_map(|i| (i as f32 * 0.125).to_le_bytes()));
        let model_input = directory.path().join("model.safetensors");
        fs::write(&model_input, tensor_bytes)?;
        let model_manifest = source.pack_file(
            &model_input,
            context(environment.id()),
            CELL_BEP52_PIECE_BYTES_V1,
        )?;
        let model = CellModelReleaseRootV1::new(
            CellReleaseClosureV1::new(
                context(environment.id()),
                2,
                [7; 32],
                vec![0],
                vec![declaration(
                    MODEL_PATH,
                    CellFileRoleV1::Base,
                    &model_manifest,
                )],
            )?,
            vec![],
        )?;
        let tensor_contract = CellTensorContractV1::new(
            model.id(),
            vec![CellTensorFileV1 {
                file_index: 0,
                tensors: vec![CellTensorSpecV1 {
                    name: "weights".into(),
                    dtype: CellTensorDTypeV1::F32,
                    shape: vec![ELEMENTS],
                }],
            }],
        )?;
        let tensor_contract_pin = tensor_contract.id();
        let model_owner = owner(model.closure(), CellFileRoleV1::Base);
        let environment_owner = owner(&environment, CellFileRoleV1::Configuration);
        let mut manifests = vec![model_manifest, environment_manifest];
        manifests.sort_by_key(CellManifestV1::id);
        let version = CellVersionManifestV1::new(model, environment, manifests)?;
        let owner_view = CellVersionLoaderContextV1 {
            commitment: version.commitment(),
            model: &model_owner,
            environment: &environment_owner,
        };
        let total_payload_bytes: u64 = version.manifests().iter().map(CellManifestV1::size).sum();
        let total_chunks: usize = version.manifests().iter().map(|m| m.chunks().len()).sum();

        evidence["stage"] = json!("native signing and independent owner pins");
        let captured = CellVersionContentV2::capture_cached(
            &version,
            &source,
            &owner_view,
            &mut content_session(deadline)?,
        )?;
        let content_pin = captured.commitment();
        // Public fixture key provisioning is separate from any peer response.
        let seed = Zeroizing::new([93; 32]);
        let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
        let key_id = ml_dsa_65_key_id_from_spki(&spki)
            .map_err(|_| CellErrorV1::Invalid("fixture ML-DSA SPKI"))?;
        let signing_key = PqNativeSigningKey::from_owned_seed(seed, key_id)?;
        let key_pin = CellPqKeyPinV2 {
            key_id,
            generation: 2,
            spki,
            not_before: timestamp.saturating_sub(1),
            expires_at: timestamp + 300,
            revoked_at: None,
        };
        let signed = CellPqContentAuthorizationV4::sign(
            CellPqContentStatementV4 {
                network: [8; 32],
                parameters: [9; 32],
                content: content_pin,
                signer_key_id: key_pin.key_id,
                signer_spki_sha512: CellPqContentStatementV4::signer_commitment(&key_pin.spki),
                generation: key_pin.generation,
                sequence: 1,
                issued_at: timestamp,
                expires_at: timestamp + 300,
                withdrawn: false,
            },
            &signing_key,
        )?;
        let signed_wire = signed.encode()?;
        let received_content = CellVersionContentV2::decode(&captured.encode())?;
        let received_authorization = CellPqContentAuthorizationV4::decode(&signed_wire)?;
        let mut expected = CellPqContentExpectationV4 {
            authority: CellPqReleaseExpectationV2 {
                network: [8; 32],
                parameters: [9; 32],
                key: &key_pin,
                sequence: 1,
                now: timestamp,
            },
            loader: owner_view,
            content: content_pin,
        };
        let pinned_content = received_content.pin_for_owner(&expected.loader, content_pin)?;
        evidence["publisher"] = json!({
            "tcv2_commitment": hex::encode(content_pin),
            "tcv2_wire_bytes": captured.encode().len(),
            "cpv4_wire_bytes": signed_wire.len(),
            "signer_key_id": hex::encode(key_id),
            "manifest_count": version.manifests().len(),
            "declared_payload_bytes": total_payload_bytes,
            "declared_chunks": total_chunks,
        });
        let mut read_session = content_session(deadline)?;
        let mut corrupted = signed_wire;
        *corrupted.last_mut().ok_or("empty CPV4 encoding")? ^= 1;
        let rejected = CellPqContentAuthorizationV4::decode(&corrupted)?.verify_cached_at(
            &received_content,
            &consumer,
            &expected,
            &mut read_session,
        );
        check(
            matches!(
                rejected.as_ref(),
                Err(CellErrorV1::Invalid("PQ content signature"))
            ) && read_session.usage().attempted_scans == 0,
            "altered CPV4 signature must fail before payload I/O",
        )?;
        evidence["negative_controls"]["corrupt_signature_error"] =
            json!(rejected.err().map(|error| error.to_string()));

        evidence["stage"] = json!("real TCP metadata and complete payload transfer");
        let mut client = peer_session([42; 32], deadline, version.manifests().len() as u64)?;
        for manifest in received_content.version().manifests() {
            let binding = CellBep52BindingV1::from_pinned_manifest(
                manifest,
                manifest.id(),
                manifest.context(),
            )?;
            transfer(
                &source_path,
                &consumer,
                &binding,
                &pinned_content,
                &mut client,
                deadline,
                evidence,
            )?;
        }
        check(
            client.deadline() == deadline,
            "pipeline TCP deadline changed",
        )?;
        evidence["network"]["cumulative_usage"] = wire_usage(client.usage());

        evidence["stage"] = json!("CPV4 and full consumer-cache byte verification");
        expected.authority.now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let verified = received_authorization.verify_cached_at(
            &received_content,
            &consumer,
            &expected,
            &mut read_session,
        )?;
        let usage = verified.usage();
        check(
            usage.attempted_scans == 1
                && usage.reserved_payload_bytes == total_payload_bytes
                && usage.reserved_chunks == total_chunks as u64,
            "pipeline full version readback coverage",
        )?;
        evidence["consumer_readback"] = json!({
            "attempted_scans": usage.attempted_scans,
            "actual_verified_payload_bytes": usage.reserved_payload_bytes,
            "actual_verified_chunk_references": usage.reserved_chunks,
        });

        evidence["stage"] = json!("residency and both actual sealed closures");
        let authenticated = verified.content_at(&expected)?;
        let mut pool = CellResidencyV1::new(CellResidencyConfigV1 {
            max_resident_bytes: PAYLOAD_LIMIT,
            max_resident_closures: 2,
            max_chunk_references: 64,
        })?;
        let cancelled = AtomicBool::new(false);
        for (closure, owner) in [
            (authenticated.version().model().closure(), &model_owner),
            (authenticated.version().environment(), &environment_owner),
        ] {
            pool.prepare_cached(&consumer, closure, owner, deadline, &cancelled)?;
        }
        let snapshot_limits = CellSealedLoaderLimitsV1 {
            max_snapshot_bytes: PAYLOAD_LIMIT,
            max_files: 2,
        };
        let model_bundle =
            pool.seal_declared_loader(&model_owner, snapshot_limits, deadline, &cancelled)?;
        let environment_bundle =
            pool.seal_declared_loader(&environment_owner, snapshot_limits, deadline, &cancelled)?;
        let duplicate_model = authenticated.verify_sealed_version(
            &model_bundle,
            &model_bundle,
            &expected.loader,
            content_pin,
            deadline,
        );
        check(
            duplicate_model.is_err(),
            "model bundle cannot substitute for environment",
        )?;
        evidence["negative_controls"]["duplicate_model_bundle_error"] =
            json!(duplicate_model.err().map(|error| error.to_string()));
        let sealed = authenticated.verify_sealed_version(
            &model_bundle,
            &environment_bundle,
            &expected.loader,
            content_pin,
            deadline,
        )?;
        evidence["sealed"] = json!({
            "model": sealed_observation(sealed.model().bundle())?,
            "environment": sealed_observation(sealed.environment().bundle())?,
        });

        evidence["stage"] = json!("strict native tensor and environment readers");
        // Recheck current authority before consuming the same borrowed objects.
        expected.authority.now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let current = verified.content_at(&expected)?;
        let mut model_file = sealed
            .model()
            .bundle()
            .file(MODEL_PATH, CellFileRoleV1::Base)?;
        let tensors = tensor_contract.verify_reader(
            current.version().model(),
            tensor_contract_pin,
            0,
            &mut model_file,
            deadline,
        )?;
        let mut environment_file = sealed
            .environment()
            .bundle()
            .file(ENVIRONMENT_PATH, CellFileRoleV1::Configuration)?;
        let decoded_environment: Value = serde_json::from_reader(&mut environment_file)?;
        check(
            decoded_environment == environment_json,
            "actual sealed environment JSON",
        )?;
        check(
            Instant::now() < deadline,
            "pipeline original completion deadline",
        )?;
        evidence["native_readers"] = json!({
            "tensor_contract_id": hex::encode(tensors.contract_id),
            "tensor_file_payload_sha256": hex::encode(tensors.payload_sha256),
            "tensor_file_payload_bytes": tensors.payload_bytes,
            "tensor_count": tensors.tensor_count,
            "tensor_dtype": "F32",
            "tensor_shape": [ELEMENTS],
            "environment_json": decoded_environment,
            "input": "same strongly verified sealed descriptors; no payload path reopen",
        });
        evidence["stage"] = json!("complete");
        Ok(())
    }

    pub fn run() -> ObservationResult<()> {
        let started = Instant::now();
        let mut evidence = json!({
            "schema": "trnm.cell-signed-sealed-component-pipeline.v1",
            "status": "RUNNING",
            "stage": "initialization",
            "scope": "native component wiring with synthetic F32 tensor and environment JSON",
            "authority": "explicit fixture owner pins established before peer listening",
            "network": {
                "profile": CELL_BEP52_PEER_PROFILE_V1,
                "topology": "explicit loopback TCP native seed and native consumer",
                "fetches": [],
            },
            "negative_controls": {},
            "hepta_started": false,
            "hepta_ready": false,
            "final_use_granted": false,
            "gpu_operations": 0,
            "wan_sla_observed": false,
            "example_source_sha256": hex::encode(Sha256::digest(include_bytes!("cell_signed_sealed_pipeline_v1.rs"))),
            "component_source_sha256": {
                "cpv4": hex::encode(Sha256::digest(include_bytes!("../src/cell/pq/content.rs"))),
                "tcv2": hex::encode(Sha256::digest(include_bytes!("../src/cell/version_content.rs"))),
                "tcp_peer": hex::encode(Sha256::digest(include_bytes!("../src/cell/bep52_peer.rs"))),
                "sealed_loader": hex::encode(Sha256::digest(include_bytes!("../src/cell/residency/sealed_loader.rs"))),
                "strict_tensor_reader": hex::encode(Sha256::digest(include_bytes!("../src/cell/tensor.rs"))),
            },
        });
        let result = observe(&mut evidence);
        evidence["elapsed_wall_ns"] = json!(started.elapsed().as_nanos());
        match &result {
            Ok(()) => evidence["status"] = json!("PASS_COMPONENT_PIPELINE"),
            Err(error) => {
                evidence["status"] = json!("FAILED_COMPONENT_PIPELINE");
                evidence["error"] = json!(error.to_string());
            }
        }
        println!("{}", serde_json::to_string_pretty(&evidence)?);
        result
    }
}
