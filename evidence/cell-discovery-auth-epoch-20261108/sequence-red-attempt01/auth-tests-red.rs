use super::*;
use crate::cell::{
    discovery::pq::CellProviderStatementV3,
    discovery::{CellDiscoveryContextV1, CellDiscoveryRequestV1},
    serve_cells, CellCacheConfigV4, CellContextV1,
};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, sync::Arc};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn context() -> CellDiscoveryContextV1 {
    CellDiscoveryContextV1 {
        namespace: [1; 32],
        network: [2; 32],
        parameters: [3; 32],
        genesis: [4; 32],
    }
}
fn cell_context() -> CellContextV1 {
    CellContextV1 {
        family: "auth-discovery-v3".into(),
        base: [5; 32],
        parent: [6; 32],
        tokenizer: [7; 32],
        layout: [8; 32],
        runtime: [9; 32],
    }
}
fn request(manifest: CellDigestV1, now: u64) -> CellDiscoveryRequestV3 {
    CellDiscoveryRequestV3 {
        base: CellDiscoveryRequestV1 {
            context: context(),
            cell_context: cell_discovery_context_digest(&cell_context()).unwrap(),
            manifest,
        },
        epoch: CellDiscoveryRequestV3::epoch_at(now),
    }
}
fn key_and_pin(seed: u8) -> (PqNativeSigningKey, CellPqKeyPinV2) {
    let seed = Zeroizing::new([seed; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    let key_id = ml_dsa_65_key_id_from_spki(&spki).unwrap();
    (
        PqNativeSigningKey::from_owned_seed(seed, key_id).unwrap(),
        CellPqKeyPinV2 {
            key_id,
            generation: 1,
            spki,
            not_before: 1,
            expires_at: u64::MAX,
            revoked_at: None,
        },
    )
}
fn policy(peers: &[SocketAddr]) -> CellDiscoveryAddressPolicyV1 {
    let mut ports: Vec<_> = peers.iter().map(SocketAddr::port).collect();
    ports.sort_unstable();
    ports.dedup();
    CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports }
}
fn limits() -> CellPeerLimitsV1 {
    CellPeerLimitsV1 {
        request_timeout: Duration::from_secs(2),
        overall_timeout: Duration::from_secs(10),
        max_cell_bytes: 1_048_576,
        parallelism: 1,
        max_connections: 64,
        max_response_bytes: 2_097_152,
    }
}
fn cache() -> CellCacheConfigV4 {
    CellCacheConfigV4 {
        max_database_bytes: 4_194_304,
        max_logical_bytes: 2_097_152,
        max_chunk_rows: 256,
        max_manifest_rows: 64,
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn epoch_now() -> u64 {
    let now = wall_now().unwrap().as_secs();
    let left = 300 - now % 300;
    // Fixture preparation occurs before any measured operation/deadline. Keep
    // this positive within-epoch TCP cohort away from the separate epoch-close
    // tests, without changing any request/service deadline.
    if left < 20 {
        eprintln!("authenticated-v3 fixture preparation: epoch remaining={left}s, wait={left}s before creating the original operation");
        thread::sleep(Duration::from_secs(left));
    }
    wall_now().unwrap().as_secs()
}
fn bootstrap(endpoint: SocketAddr, pin: &CellPqKeyPinV2) -> CellBootstrapPinV3 {
    CellBootstrapPinV3 {
        endpoint,
        key_id: pin.key_id,
        generation: pin.generation,
    }
}
fn query_at(request: CellDiscoveryRequestV3, bootstrap: CellBootstrapPinV3, now: u64) -> Query {
    Query {
        nonce: [99; 32],
        request,
        bootstrap,
        issued_at: now,
        expires_at: (now + 15).min(request.epoch_bounds().unwrap().1),
        record: Vec::new(),
        signature: [0; ML_DSA_65_SIGNATURE_BYTES],
    }
}
fn record(
    request: CellDiscoveryRequestV3,
    endpoint: SocketAddr,
    sequence: u64,
    now: u64,
    key: &PqNativeSigningKey,
    withdrawn: bool,
) -> CellProviderRecordV3 {
    CellProviderRecordV3::sign(
        CellProviderStatementV3 {
            request,
            owner: key.public_key_id(),
            owner_generation: 1,
            endpoint,
            sequence,
            issued_unix_seconds: now,
            expires_unix_seconds: (now + 120).min(request.epoch_bounds().unwrap().1),
            withdrawn,
        },
        key,
    )
    .unwrap()
}
fn verify_frame(query: &Query, keys: &CellPqKeyPinsV2, wire: &[u8]) -> CellResultV1<Reply> {
    let header: [u8; RESPONSE_HEADER_BYTES] = wire[..RESPONSE_HEADER_BYTES].try_into().unwrap();
    let mut observation = CellDiscoveryObservationV3::default();
    observation.reserve(SignatureKind::Bootstrap)?;
    verify_response(
        query,
        keys,
        ReceivedResponse {
            header: &header,
            body_and_signature: &wire[RESPONSE_HEADER_BYTES..],
            time: CellDiscoveryTimeV3::sample()?,
        },
        deadline(),
        deadline(),
        &mut observation,
    )
}

#[test]
fn authenticated_v3_query_codec_matches_independent_fixed_preimage() {
    let query = Query {
        nonce: [7; 32],
        request: CellDiscoveryRequestV3 {
            base: CellDiscoveryRequestV1 {
                context: context(),
                cell_context: [5; 32],
                manifest: [6; 32],
            },
            epoch: 3,
        },
        bootstrap: CellBootstrapPinV3 {
            endpoint: "127.0.0.1:19001".parse().unwrap(),
            key_id: [8; 32],
            generation: 9,
        },
        issued_at: 1000,
        expires_at: 1010,
        record: Vec::new(),
        signature: [0; ML_DSA_65_SIGNATURE_BYTES],
    };
    let wire = query.encode();
    assert_eq!(wire.len(), 319);
    assert_eq!(
        &wire[..12],
        &[b'C', b'D', b'Q', b'3', 3, 0x65, 1, 0, 0, 0, 0, 0]
    );
    assert_eq!(Query::decode(&wire).unwrap().encode(), wire);
    // SHA-256 receipts independently generated with Python struct.pack, six
    // fixed 32-byte context fields, and ipaddress.IPv4Address.packed.
    assert_eq!(
        hex::encode(Sha256::digest(&wire)),
        "3e07d8aeedf05cd982dafa76c835c612cc704d3ab37c17abf104509268ebe88f"
    );
    let reply = response_unsigned(&query, 0, &[0], 1001, 1010).unwrap();
    assert_eq!(reply.len(), 29);
    assert_eq!(
        hex::encode(Sha256::digest(&reply)),
        "bb4b7bd17c9235649905ba1ad133b78428e850c01877ccb1c9f1a0063b9a9df7"
    );
    assert_eq!(
        hex::encode(Sha256::digest(response_message(&query, &reply))),
        "6bbb01720438337b3807497e0921aa88b05330642ba6b4835b90f7708943d8a8"
    );
    let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../formal/pon-nakamoto-v1/vectors/cell-discovery-epoch-v3.json"
    )))
    .unwrap();
    for (name, actual) in [
        ("query", wire.clone()),
        ("unsigned_reply", reply.clone()),
        ("reply_signature_message", response_message(&query, &reply)),
    ] {
        assert_eq!(
            actual,
            hex::decode(
                vector["authenticated_lookup"][name]["hex"]
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
            "independent {name} bytes"
        );
    }
    for size in [0, 318, 320, MAX_QUERY_BYTES + 1] {
        let mut changed = wire.clone();
        changed.resize(size, 0);
        assert!(Query::decode(&changed).is_err(), "accepted size {size}");
    }
    for (index, value) in [(3, b'2'), (4, 2), (5, 0), (6, 0), (7, 1), (11, 1), (244, 0)] {
        let mut changed = wire.clone();
        changed[index] = value;
        assert!(
            Query::decode(&changed).is_err(),
            "accepted encoding byte {index}"
        );
    }
}

#[test]
fn authenticated_v3_nonce_is_fresh_and_rng_failure_does_not_fallback() {
    let now = epoch_now();
    let (_, pin) = key_and_pin(42);
    let bootstrap = bootstrap("127.0.0.1:19001".parse().unwrap(), &pin);
    let request = request([20; 32], now);
    let attempts = AtomicU64::new(2);
    let responses = ResponseBudget::new(10_000);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: deadline(),
        requests_left: &attempts,
        responses: &responses,
    };
    let first = Query::fresh(request, bootstrap, &transport, Vec::new()).unwrap();
    let second = Query::fresh(request, bootstrap, &transport, Vec::new()).unwrap();
    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.nonce, [0; 32]);
    assert!(
        Query::fresh_with_nonce(request, bootstrap, &transport, Vec::new(), |_| Err(
            CellErrorV1::Invalid("test entropy unavailable")
        ))
        .is_err()
    );
    assert!(
        Query::fresh_with_nonce(request, bootstrap, &transport, Vec::new(), |_| Ok(())).is_err()
    );
    assert_eq!(attempts.load(Ordering::Relaxed), 2);
    assert_eq!(responses.received().unwrap(), 0);
}

#[test]
fn authenticated_v3_signature_binds_nonce_every_request_field_epoch_target_and_status() {
    let now = epoch_now();
    let (key, pin) = key_and_pin(42);
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let query = query_at(
        request([20; 32], now),
        bootstrap("127.0.0.1:19001".parse().unwrap(), &pin),
        now,
    );
    let wire = signed_response(&query, 0, &[0], now, query.expires_at, &key).unwrap();
    assert_eq!(verify_frame(&query, &keys, &wire).unwrap().body, vec![0]);
    let mut changed_queries = Vec::new();
    let mut changed = query.clone();
    changed.nonce[0] ^= 1;
    changed_queries.push(changed);
    let mut changed = query.clone();
    changed.request.base.context.namespace[0] ^= 1;
    changed_queries.push(changed);
    let mut changed = query.clone();
    changed.request.base.context.network[0] ^= 1;
    changed_queries.push(changed);
    let mut changed = query.clone();
    changed.request.base.context.parameters[0] ^= 1;
    changed_queries.push(changed);
    let mut changed = query.clone();
    changed.request.base.context.genesis[0] ^= 1;
    changed_queries.push(changed);
    let mut changed = query.clone();
    changed.request.base.cell_context[0] ^= 1;
    changed_queries.push(changed);
    let mut changed = query.clone();
    changed.request.base.manifest[0] ^= 1;
    changed_queries.push(changed);
    let mut changed = query.clone();
    changed.request.epoch += 1;
    changed_queries.push(changed);
    let mut changed = query.clone();
    changed.bootstrap.endpoint.set_port(19002);
    changed_queries.push(changed);
    let mut changed = query.clone();
    changed.bootstrap.key_id[0] ^= 1;
    changed_queries.push(changed);
    let mut changed = query.clone();
    changed.bootstrap.generation += 1;
    changed_queries.push(changed);
    let mut changed = query.clone();
    changed.issued_at = changed.issued_at.saturating_sub(1);
    changed_queries.push(changed);
    let mut changed = query.clone();
    changed.expires_at -= 1;
    changed_queries.push(changed);
    for (index, changed) in changed_queries.iter().enumerate() {
        assert!(
            verify_frame(changed, &keys, &wire).is_err(),
            "accepted changed query {index}"
        );
    }
    for index in [0, 3, 4, 5, 6, 7, 15, 23, 27, 28, 29, wire.len() - 1] {
        let mut changed = wire.clone();
        changed[index] ^= 1;
        assert!(
            verify_frame(&query, &keys, &changed).is_err(),
            "accepted changed response byte {index}"
        );
    }
    let (_, wrong_pin) = key_and_pin(43);
    assert!(verify_frame(
        &query,
        &CellPqKeyPinsV2::new(vec![wrong_pin]).unwrap(),
        &wire
    )
    .is_err());
}

#[test]
fn authenticated_v3_revoked_authority_and_duplicate_source_keys_fail_before_dial() {
    let now = epoch_now();
    let (key, mut pin) = key_and_pin(42);
    let address = "127.0.0.1:19001".parse().unwrap();
    let query = query_at(request([20; 32], now), bootstrap(address, &pin), now);
    let wire = signed_response(&query, 0, &[0], now, query.expires_at, &key).unwrap();
    pin.revoked_at = Some(now);
    let revoked = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    assert!(verify_frame(&query, &revoked, &wire).is_err());
    let mut options = CellDiscoveryOptionsV3 {
        request: query.request,
        bootstraps: vec![bootstrap(address, &pin)],
        bootstrap_keys: revoked,
        addresses: policy(&[address]),
    };
    options.validate_at(now).unwrap();
    let attempts = AtomicU64::new(1);
    let responses = ResponseBudget::new(10_000);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: deadline(),
        requests_left: &attempts,
        responses: &responses,
    };
    let mut observation = CellDiscoveryObservationV3::default();
    assert!(matches!(
        exchange(
            &query,
            &options.bootstrap_keys,
            &transport,
            &mut observation
        ),
        Err(CellErrorV1::Invalid("PQ Cell key expired/revoked"))
    ));
    assert_eq!(observation.connection_attempts, 0);
    assert_eq!(observation.signature_attempts(), 0);
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    pin.revoked_at = None;
    options.bootstrap_keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    options.validate_at(now).unwrap();
    let second = "127.0.0.1:19002".parse().unwrap();
    options.addresses = policy(&[address, second]);
    options.bootstraps.push(bootstrap(second, &pin));
    assert!(options.source_pins().is_err());
    assert!(options.validate_at(now).is_err());
}

#[test]
fn authenticated_v3_forged_capacity_status_is_not_a_trusted_capacity_receipt() {
    let now = epoch_now();
    let (key, pin) = key_and_pin(42);
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let query = query_at(
        request([20; 32], now),
        bootstrap("127.0.0.1:19001".parse().unwrap(), &pin),
        now,
    );
    let wire = signed_response(&query, 2, &[], now, query.expires_at, &key).unwrap();
    for authentic in [false, true] {
        let mut raw = wire.clone();
        if !authentic {
            *raw.last_mut().unwrap() ^= 1;
        }
        let header = raw[..RESPONSE_HEADER_BYTES].try_into().unwrap();
        let mut observation = CellDiscoveryObservationV3::default();
        observation.reserve(SignatureKind::Bootstrap).unwrap();
        let result = verify_response(
            &query,
            &keys,
            ReceivedResponse {
                header,
                body_and_signature: &raw[RESPONSE_HEADER_BYTES..],
                time: CellDiscoveryTimeV3::sample().unwrap(),
            },
            deadline(),
            deadline(),
            &mut observation,
        );
        assert!(result.is_err());
        assert_eq!(observation.capacity_rejections, usize::from(authentic));
        assert_eq!(observation.signature_attempts(), 1);
    }
}

struct Rendezvous {
    bootstrap: CellBootstrapPinV3,
    authority: CellPqKeyPinV2,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<CellRendezvousReportV3>>,
}
impl Rendezvous {
    fn start(
        path: &Path,
        providers: CellPqKeyPinsV2,
        source_pins: CellDiscoverySourcePinsV3,
        allowed: &[SocketAddr],
        seed: u8,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (key, authority) = key_and_pin(seed);
        let bootstrap = bootstrap(address, &authority);
        let directory =
            CellProviderDirectoryV3::open(path, context(), providers, source_pins).unwrap();
        let mut peers = allowed.to_vec();
        peers.push(address);
        let addresses = policy(&peers);
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let pin = authority.clone();
        let worker = thread::spawn(move || {
            let identity = CellRendezvousIdentityV3 {
                bootstrap,
                key: &key,
                authority: &pin,
            };
            serve_authenticated_cell_rendezvous_pq(
                &listener,
                &directory,
                &addresses,
                &identity,
                &shutdown,
                CellRendezvousLimitsV2 {
                    request_timeout: Duration::from_secs(2),
                    lifetime: Duration::from_secs(20),
                    max_connections: 64,
                },
            )
            .unwrap()
        });
        Self {
            bootstrap,
            authority,
            stop,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> CellRendezvousReportV3 {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for Rendezvous {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn provider_sources(pin: &CellPqKeyPinV2) -> CellDiscoverySourcePinsV3 {
    CellDiscoverySourcePinsV3::new(vec![CellDiscoverySourcePinV3 {
        authenticated_key_id: pin.key_id,
        generation: pin.generation,
        ip: "127.0.0.1".parse().unwrap(),
    }])
    .unwrap()
}

struct Cells {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Cells {
    fn start(path: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let path = path.to_path_buf();
        let worker = thread::spawn(move || {
            let store = CellStoreV1::open(&path, cache()).unwrap();
            serve_cells(&listener, &store, &shutdown, limits()).unwrap();
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Cells {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn authenticated_v3_real_tcp_announce_cold_fetch_and_withdrawal_share_original_session() {
    let now = epoch_now();
    let tmp = tempfile::tempdir().unwrap();
    let bytes: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
    let input = tmp.path().join("input");
    fs::write(&input, &bytes).unwrap();
    let origin_path = tmp.path().join("origin");
    let origin = CellStoreV1::open(&origin_path, cache()).unwrap();
    let manifest = origin.pack_file(&input, cell_context(), 16_384).unwrap();
    drop(origin);
    let cells = Cells::start(&origin_path);
    let (provider_key, provider_pin) = key_and_pin(41);
    let provider_keys = CellPqKeyPinsV2::new(vec![provider_pin.clone()]).unwrap();
    let rendezvous = Rendezvous::start(
        &tmp.path().join("rendezvous"),
        provider_keys.clone(),
        provider_sources(&provider_pin),
        &[cells.address],
        42,
    );
    let request = request(manifest.id(), now);
    let options = CellDiscoveryOptionsV3 {
        request,
        bootstraps: vec![rendezvous.bootstrap],
        bootstrap_keys: CellPqKeyPinsV2::new(vec![rendezvous.authority.clone()]).unwrap(),
        addresses: policy(&[cells.address, rendezvous.bootstrap.endpoint]),
    };
    let advert = record(request, cells.address, 1, now, &provider_key, false);
    let announced = announce_authenticated_cell_provider_pq(
        &advert,
        &provider_key,
        &provider_keys,
        &options,
        limits(),
        deadline(),
    )
    .unwrap();
    assert_eq!(announced.connection_attempts, 1);
    assert_eq!(announced.signature_attempts(), 3);
    assert_eq!(
        announced.received_response_bytes,
        (RESPONSE_HEADER_BYTES + 32 + ML_DSA_65_SIGNATURE_BYTES) as u64
    );
    let client = CellProviderDirectoryV3::open(
        &tmp.path().join("client-directory"),
        context(),
        provider_keys.clone(),
        options.source_pins().unwrap(),
    )
    .unwrap();
    let store = CellStoreV1::open(&tmp.path().join("client-cache"), cache()).unwrap();
    let output = tmp.path().join("complete");
    let (_, report) = fetch_authenticated_discovered_cell_to_file_pq(
        &store,
        &client,
        &options,
        limits(),
        deadline(),
        &output,
    )
    .unwrap();
    assert_eq!(fs::read(&output).unwrap(), bytes);
    assert_eq!(report.discovered_providers, vec![cells.address]);
    assert!(!report.manifest_initial_cache_hit);
    assert_eq!(report.fetch.cached_chunks, 0);
    assert_eq!(report.discovery.record_validation_attempts, 1);
    assert_eq!(report.discovery.bootstrap_validation_attempts, 1);
    assert_eq!(report.discovery.signature_attempts(), 2);
    assert_eq!(report.discovery.connection_attempts, 1);
    assert_eq!(
        report.discovery.received_response_bytes,
        (RESPONSE_HEADER_BYTES + 1 + CELL_PROVIDER_RECORD_BYTES_V3 + ML_DSA_65_SIGNATURE_BYTES)
            as u64
    );
    assert!(report.fetch.connection_attempts > report.discovery.connection_attempts);
    assert!(
        report.fetch.received_response_bytes
            >= report.discovery.received_response_bytes + bytes.len() as u64
    );
    assert_eq!(
        client
            .usage_at(wall_now().unwrap().as_secs(), deadline())
            .unwrap()
            .active_identities,
        1
    );
    let now = wall_now().unwrap().as_secs();
    let withdrawn = record(request, cells.address, 2, now, &provider_key, true);
    announce_authenticated_cell_provider_pq(
        &withdrawn,
        &provider_key,
        &provider_keys,
        &options,
        limits(),
        deadline(),
    )
    .unwrap();
    let blocked = tmp.path().join("withdrawn-output");
    assert!(fetch_authenticated_discovered_cell_to_file_pq(
        &store,
        &client,
        &options,
        limits(),
        deadline(),
        &blocked
    )
    .is_err());
    assert!(!blocked.exists());
    assert!(announce_authenticated_cell_provider_pq(
        &advert,
        &provider_key,
        &provider_keys,
        &options,
        limits(),
        deadline()
    )
    .is_err());
    let current = client
        .records(request, wall_now().unwrap().as_secs(), deadline())
        .unwrap();
    assert_eq!(current.len(), 1);
    assert!(current[0].statement().withdrawn);
    let report = rendezvous.finish();
    assert!(report.signature_attempts() <= MAX_DISCOVERY_RECORDS);
    assert_eq!(report.connections, 5);
    assert_eq!(report.reply_signature_attempts, 5);
}

#[test]
fn authenticated_v3_revoked_first_source_does_not_block_later_source_cold_fetch() {
    let now = epoch_now();
    let tmp = tempfile::tempdir().unwrap();
    let bytes = b"A complete Cell obtained from a live independent pinned source.";
    let input = tmp.path().join("input");
    fs::write(&input, bytes).unwrap();
    let origin_path = tmp.path().join("origin");
    let origin = CellStoreV1::open(&origin_path, cache()).unwrap();
    let manifest = origin.pack_file(&input, cell_context(), 16_384).unwrap();
    drop(origin);
    let cells = Cells::start(&origin_path);
    let (provider_key, provider_pin) = key_and_pin(41);
    let provider_keys = CellPqKeyPinsV2::new(vec![provider_pin.clone()]).unwrap();
    let live = Rendezvous::start(
        &tmp.path().join("rendezvous"),
        provider_keys.clone(),
        provider_sources(&provider_pin),
        &[cells.address],
        42,
    );
    let unavailable_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    unavailable_listener.set_nonblocking(true).unwrap();
    let unavailable = unavailable_listener.local_addr().unwrap();
    let (_, mut retired_pin) = key_and_pin(43);
    retired_pin.revoked_at = Some(now);
    let request = request(manifest.id(), now);
    let mut options = CellDiscoveryOptionsV3 {
        request,
        bootstraps: vec![live.bootstrap],
        bootstrap_keys: CellPqKeyPinsV2::new(vec![live.authority.clone()]).unwrap(),
        addresses: policy(&[cells.address, live.bootstrap.endpoint, unavailable]),
    };
    let advert = record(request, cells.address, 1, now, &provider_key, false);
    announce_authenticated_cell_provider_pq(
        &advert,
        &provider_key,
        &provider_keys,
        &options,
        limits(),
        deadline(),
    )
    .unwrap();
    options
        .bootstraps
        .insert(0, bootstrap(unavailable, &retired_pin));
    options.bootstrap_keys =
        CellPqKeyPinsV2::new(vec![retired_pin, live.authority.clone()]).unwrap();
    let client = CellProviderDirectoryV3::open(
        &tmp.path().join("client-directory"),
        context(),
        provider_keys,
        options.source_pins().unwrap(),
    )
    .unwrap();
    let store = CellStoreV1::open(&tmp.path().join("client-cache"), cache()).unwrap();
    let output = tmp.path().join("complete");
    let (_, report) = fetch_authenticated_discovered_cell_to_file_pq(
        &store,
        &client,
        &options,
        limits(),
        deadline(),
        &output,
    )
    .unwrap();
    assert_eq!(fs::read(&output).unwrap(), bytes);
    assert_eq!(report.discovery.ineligible_bootstraps, 1);
    assert_eq!(report.discovery.rejected_bootstraps, 1);
    assert_eq!(report.discovery.connection_attempts, 1);
    assert_eq!(report.discovery.bootstrap_validation_attempts, 1);
    assert_eq!(report.discovery.record_validation_attempts, 1);
    assert_eq!(report.discovered_providers, vec![cells.address]);
    assert!(
        matches!(unavailable_listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    assert_eq!(live.finish().connections, 2);
}

#[test]
fn authenticated_v3_unsigned_legacy_replies_never_populate_directory_or_trigger_fallback() {
    let now = epoch_now();
    let tmp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (_, pin) = key_and_pin(42);
    let options = CellDiscoveryOptionsV3 {
        request: request([20; 32], now),
        bootstraps: vec![bootstrap(address, &pin)],
        bootstrap_keys: CellPqKeyPinsV2::new(vec![pin]).unwrap(),
        addresses: policy(&[address]),
    };
    let worker = thread::spawn(move || {
        let mut nonces = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let query = read_query(&mut stream, deadline()).unwrap();
            nonces.push(query.nonce);
            stream
                .write_all(&[b'C', b'D', b'S', b'2', 0, 0, 0, 0, 1, 0])
                .unwrap();
        }
        nonces
    });
    let (_, provider_pin) = key_and_pin(41);
    let directory = CellProviderDirectoryV3::open(
        &tmp.path().join("directory"),
        context(),
        CellPqKeyPinsV2::new(vec![provider_pin]).unwrap(),
        options.source_pins().unwrap(),
    )
    .unwrap();
    let attempts = AtomicU64::new(2);
    let responses = ResponseBudget::new(20);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: deadline(),
        requests_left: &attempts,
        responses: &responses,
    };
    let mut observation = CellDiscoveryObservationV3::default();
    assert!(discover(&directory, &options, &transport, &mut observation).is_err());
    assert_eq!(observation.connection_attempts, 2);
    assert_eq!(observation.received_response_bytes, 20);
    assert_eq!(observation.bootstrap_validation_attempts, 2);
    assert_eq!(observation.record_validation_attempts, 0);
    assert_eq!(responses.received().unwrap(), 20);
    assert_eq!(attempts.load(Ordering::Relaxed), 0);
    assert_eq!(
        directory
            .usage_at(wall_now().unwrap().as_secs(), deadline())
            .unwrap()
            .retained_identities,
        0
    );
    let nonces = worker.join().unwrap();
    assert_eq!(nonces.len(), 2);
    assert_ne!(nonces[0], nonces[1]);
}

#[test]
fn authenticated_v3_partial_reply_charges_original_byte_budget_without_refill() {
    let now = epoch_now();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (key, pin) = key_and_pin(42);
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let query = read_query(&mut stream, deadline()).unwrap();
        let wire = signed_response(
            &query,
            0,
            &[0],
            wall_now().unwrap().as_secs(),
            query.expires_at,
            &key,
        )
        .unwrap();
        let _ = stream.write_all(&wire);
    });
    let attempts = AtomicU64::new(2);
    let responses = ResponseBudget::new(13);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: deadline(),
        requests_left: &attempts,
        responses: &responses,
    };
    let query = Query::fresh(
        request([20; 32], now),
        bootstrap(address, &pin),
        &transport,
        Vec::new(),
    )
    .unwrap();
    let mut observation = CellDiscoveryObservationV3::default();
    assert!(exchange(&query, &keys, &transport, &mut observation).is_err());
    assert_eq!(observation.received_response_bytes, 13);
    assert_eq!(responses.received().unwrap(), 13);
    assert_eq!(observation.connection_attempts, 1);
    assert_eq!(observation.bootstrap_validation_attempts, 1);
    assert!(exchange(&query, &keys, &transport, &mut observation).is_err());
    assert_eq!(observation.connection_attempts, 1);
    assert_eq!(observation.bootstrap_validation_attempts, 1);
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
    worker.join().unwrap();
}

#[test]
fn authenticated_v3_combined_validation_limit_refuses_before_extra_connection() {
    let now = epoch_now();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (_, pin) = key_and_pin(42);
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let attempts = AtomicU64::new(2);
    let responses = ResponseBudget::new(10_000);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: deadline(),
        requests_left: &attempts,
        responses: &responses,
    };
    let query = Query::fresh(
        request([20; 32], now),
        bootstrap(address, &pin),
        &transport,
        Vec::new(),
    )
    .unwrap();
    let mut observation = CellDiscoveryObservationV3 {
        record_validation_attempts: 56,
        bootstrap_validation_attempts: 8,
        ..Default::default()
    };
    assert!(matches!(
        exchange(&query, &keys, &transport, &mut observation),
        Err(CellErrorV1::Invalid(
            "authenticated discovery combined signature budget"
        ))
    ));
    assert_eq!(observation.signature_attempts(), 64);
    assert_eq!(observation.connection_attempts, 0);
    assert_eq!(attempts.load(Ordering::Relaxed), 2);
    assert_eq!(responses.received().unwrap(), 0);
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}

struct SignedSource {
    bootstrap: CellBootstrapPinV3,
    authority: CellPqKeyPinV2,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Vec<[u8; 32]>>>,
}
impl SignedSource {
    fn start(seed: u8, body: Vec<u8>, delay: Duration, count: usize) -> Self {
        Self::start_sequence(seed, vec![body; count], delay)
    }
    fn start_sequence(seed: u8, bodies: Vec<Vec<u8>>, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (key, authority) = key_and_pin(seed);
        let bootstrap = bootstrap(address, &authority);
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let overall = Instant::now() + Duration::from_secs(20);
            let mut nonces = Vec::new();
            while !shutdown.load(Ordering::Relaxed)
                && nonces.len() < bodies.len()
                && Instant::now() < overall
            {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let query = read_query(
                            &mut stream,
                            overall.min(Instant::now() + Duration::from_secs(2)),
                        )
                        .unwrap();
                        assert_eq!(query.bootstrap, bootstrap);
                        nonces.push(query.nonce);
                        if !delay.is_zero() {
                            thread::sleep(delay);
                        }
                        let wire = signed_response(
                            &query,
                            0,
                            &bodies[nonces.len() - 1],
                            wall_now().unwrap().as_secs(),
                            query.expires_at,
                            &key,
                        )
                        .unwrap();
                        let _ = stream.write_all(&wire);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("scripted bootstrap accept: {error}"),
                }
            }
            nonces
        });
        Self {
            bootstrap,
            authority,
            stop,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> Vec<[u8; 32]> {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for SignedSource {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn authenticated_v3_real_tcp_receipt_time_equivocation_survives_later_source_expiry() {
    let (provider_key, provider_pin) = key_and_pin(41);
    let provider_keys = CellPqKeyPinsV2::new(vec![provider_pin]).unwrap();
    let first_endpoint: SocketAddr = "127.0.0.1:19001".parse().unwrap();
    let later_endpoint: SocketAddr = "127.0.0.2:19001".parse().unwrap();
    for later_sequence in [1, 2] {
        epoch_now();
        // Prepare the short lease near a real wall second's start. This occurs
        // before the original operation is created; the deliberately slow
        // second source still has the unchanged two-second request timeout.
        let wall = wall_now().unwrap();
        let fractional = wall - Duration::from_secs(wall.as_secs());
        if fractional > Duration::from_millis(100) {
            thread::sleep(Duration::from_secs(1) - fractional);
        }
        let now = wall_now().unwrap().as_secs();
        let request = request([20; 32], now);
        let short = CellProviderRecordV3::sign(
            CellProviderStatementV3 {
                request,
                owner: provider_key.public_key_id(),
                owner_generation: 1,
                endpoint: first_endpoint,
                sequence: 1,
                issued_unix_seconds: now,
                expires_unix_seconds: now + 1,
                withdrawn: false,
            },
            &provider_key,
        )
        .unwrap();
        let later = record(
            request,
            later_endpoint,
            later_sequence,
            now,
            &provider_key,
            false,
        );
        let mut first_body = vec![1];
        first_body.extend(short.encode());
        let mut later_body = vec![1];
        later_body.extend(later.encode());
        let first = SignedSource::start(42, first_body, Duration::ZERO, 1);
        let second = SignedSource::start(43, later_body, Duration::from_millis(1_200), 1);
        let options = CellDiscoveryOptionsV3 {
            request,
            bootstraps: vec![first.bootstrap, second.bootstrap],
            bootstrap_keys: CellPqKeyPinsV2::new(vec![
                first.authority.clone(),
                second.authority.clone(),
            ])
            .unwrap(),
            addresses: policy(&[
                first_endpoint,
                later_endpoint,
                first.bootstrap.endpoint,
                second.bootstrap.endpoint,
            ]),
        };
        let tmp = tempfile::tempdir().unwrap();
        let directory = CellProviderDirectoryV3::open(
            &tmp.path().join("directory"),
            context(),
            provider_keys.clone(),
            options.source_pins().unwrap(),
        )
        .unwrap();
        let attempts = AtomicU64::new(2);
        let bytes = 2
            * (RESPONSE_HEADER_BYTES
                + 1
                + CELL_PROVIDER_RECORD_BYTES_V3
                + ML_DSA_65_SIGNATURE_BYTES) as u64;
        let responses = ResponseBudget::new(bytes);
        let transport = RequestContext {
            cancelled: None,
            timeout: Duration::from_secs(2),
            overall: deadline(),
            requests_left: &attempts,
            responses: &responses,
        };
        let mut observation = CellDiscoveryObservationV3::default();
        let result = discover(&directory, &options, &transport, &mut observation);
        if later_sequence == 1 {
            assert!(
                result.is_err(),
                "expired receipt-time conflict was forgotten"
            );
            assert_eq!(
                directory
                    .usage_at(wall_now().unwrap().as_secs(), deadline())
                    .unwrap()
                    .retained_identities,
                0
            );
        } else {
            assert_eq!(
                result.unwrap().0,
                vec![later_endpoint],
                "a non-conflicting newer sequence should survive"
            );
            assert_eq!(
                directory
                    .usage_at(wall_now().unwrap().as_secs(), deadline())
                    .unwrap()
                    .retained_identities,
                1
            );
        }
        assert!(wall_now().unwrap().as_secs() >= short.statement().expires_unix_seconds);
        assert_eq!(observation.connection_attempts, 2);
        assert_eq!(observation.bootstrap_validation_attempts, 2);
        assert_eq!(observation.record_validation_attempts, 2);
        assert_eq!(observation.signature_attempts(), 4);
        assert_eq!(observation.received_response_bytes, bytes);
        assert_eq!(responses.received().unwrap(), bytes);
        assert_eq!(attempts.load(Ordering::Relaxed), 0);
        assert_eq!(first.finish().len(), 1);
        assert_eq!(second.finish().len(), 1);
    }
}

#[test]
fn authenticated_v3_real_tcp_eight_queries_and_bad_records_share_all_sixty_four_slots() {
    let now = epoch_now();
    let tmp = tempfile::tempdir().unwrap();
    let (provider_key, provider_pin) = key_and_pin(41);
    let request = request([20; 32], now);
    let endpoint = "127.0.0.1:19001".parse().unwrap();
    let good = record(request, endpoint, 1, now, &provider_key, false).encode();
    let mut body = vec![7];
    for index in 0..7 {
        let mut corrupt = good.clone();
        corrupt[291 + index] ^= 1;
        body.extend(corrupt);
    }
    let sources: Vec<_> = (42..=45)
        .map(|seed| SignedSource::start(seed, body.clone(), Duration::ZERO, 2))
        .collect();
    let mut addresses = vec![endpoint];
    addresses.extend(sources.iter().map(|source| source.bootstrap.endpoint));
    let options = CellDiscoveryOptionsV3 {
        request,
        bootstraps: sources.iter().map(|source| source.bootstrap).collect(),
        bootstrap_keys: CellPqKeyPinsV2::new(
            sources
                .iter()
                .map(|source| source.authority.clone())
                .collect(),
        )
        .unwrap(),
        addresses: policy(&addresses),
    };
    let directory = CellProviderDirectoryV3::open(
        &tmp.path().join("directory"),
        context(),
        CellPqKeyPinsV2::new(vec![provider_pin]).unwrap(),
        options.source_pins().unwrap(),
    )
    .unwrap();
    let attempts = AtomicU64::new(8);
    let bytes = 8 * (RESPONSE_HEADER_BYTES + body.len() + ML_DSA_65_SIGNATURE_BYTES) as u64;
    let responses = ResponseBudget::new(bytes);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: deadline(),
        requests_left: &attempts,
        responses: &responses,
    };
    let mut observation = CellDiscoveryObservationV3::default();
    assert!(discover(&directory, &options, &transport, &mut observation).is_err());
    assert_eq!(observation.connection_attempts, 8);
    assert_eq!(observation.bootstrap_validation_attempts, 8);
    assert_eq!(observation.record_validation_attempts, 56);
    assert_eq!(observation.rejected_records, 56);
    assert_eq!(observation.signature_attempts(), 64);
    assert_eq!(observation.received_response_bytes, bytes);
    assert_eq!(responses.received().unwrap(), bytes);
    assert_eq!(attempts.load(Ordering::Relaxed), 0);
    assert_eq!(
        directory
            .usage_at(wall_now().unwrap().as_secs(), deadline())
            .unwrap()
            .retained_identities,
        0
    );
    for source in sources {
        let nonces = source.finish();
        assert_eq!(nonces.len(), 2);
        assert_ne!(nonces[0], nonces[1]);
    }
}

#[test]
fn authenticated_v3_old_record_alone_and_unpinned_announcement_source_cannot_mutate_directory() {
    let now = epoch_now();
    let tmp = tempfile::tempdir().unwrap();
    let (provider_key, provider_pin) = key_and_pin(41);
    let provider_keys = CellPqKeyPinsV2::new(vec![provider_pin.clone()]).unwrap();
    let endpoint = "127.0.0.1:19001".parse().unwrap();
    let request = request([20; 32], now);
    let advert = record(request, endpoint, 1, now, &provider_key, false);
    for signed_query in [false, true] {
        let sources = CellDiscoverySourcePinsV3::new(vec![CellDiscoverySourcePinV3 {
            authenticated_key_id: provider_pin.key_id,
            generation: 1,
            ip: if signed_query {
                "127.0.0.2"
            } else {
                "127.0.0.1"
            }
            .parse()
            .unwrap(),
        }])
        .unwrap();
        let path = tmp.path().join(if signed_query {
            "wrong-source"
        } else {
            "unsigned-query"
        });
        let server = Rendezvous::start(
            &path,
            provider_keys.clone(),
            sources.clone(),
            &[endpoint],
            42,
        );
        let keys = CellPqKeyPinsV2::new(vec![server.authority.clone()]).unwrap();
        let attempts = AtomicU64::new(1);
        let responses = ResponseBudget::new(10_000);
        let transport = RequestContext {
            cancelled: None,
            timeout: Duration::from_secs(2),
            overall: deadline(),
            requests_left: &attempts,
            responses: &responses,
        };
        let mut query =
            Query::fresh(request, server.bootstrap, &transport, advert.encode()).unwrap();
        if signed_query {
            query.signature = provider_key
                .sign_exact_message(&query.announcement_message())
                .unwrap();
        }
        let mut observation = CellDiscoveryObservationV3::default();
        assert!(matches!(
            exchange(&query, &keys, &transport, &mut observation),
            Err(CellErrorV1::Invalid("authenticated discovery denied reply"))
        ));
        let report = server.finish();
        assert_eq!(report.connections, 1);
        assert_eq!(report.record_validation_attempts, 1);
        assert_eq!(report.announcement_validation_attempts, 1);
        assert_eq!(report.reply_signature_attempts, 1);
        assert_eq!(report.signature_attempts(), 3);
        let directory =
            CellProviderDirectoryV3::open(&path, context(), provider_keys.clone(), sources)
                .unwrap();
        assert_eq!(
            directory
                .usage_at(wall_now().unwrap().as_secs(), deadline())
                .unwrap()
                .retained_identities,
            0
        );
    }
}

#[test]
fn authenticated_v3_oversized_local_durations_are_typed_refusals_before_side_effects() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let now = epoch_now();
    let tmp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (key, pin) = key_and_pin(42);
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let options = CellDiscoveryOptionsV3 {
        request: request([20; 32], now),
        bootstraps: vec![bootstrap(address, &pin)],
        bootstrap_keys: keys.clone(),
        addresses: policy(&[address]),
    };
    let directory = CellProviderDirectoryV3::open(
        &tmp.path().join("directory"),
        context(),
        keys.clone(),
        options.source_pins().unwrap(),
    )
    .unwrap();
    let store = CellStoreV1::open(&tmp.path().join("store"), cache()).unwrap();
    let mut invalid_limits = limits();
    invalid_limits.overall_timeout = Duration::MAX;
    let output = tmp.path().join("not-created");
    assert!(catch_unwind(AssertUnwindSafe(|| {
        fetch_authenticated_discovered_cell_to_file_pq(
            &store,
            &directory,
            &options,
            invalid_limits,
            deadline(),
            &output,
        )
    }))
    .unwrap()
    .is_err());
    let advert = record(options.request, address, 1, now, &key, false);
    assert!(catch_unwind(AssertUnwindSafe(
        || announce_authenticated_cell_provider_pq(
            &advert,
            &key,
            &keys,
            &options,
            invalid_limits,
            deadline()
        )
    ))
    .unwrap()
    .is_err());
    let identity = CellRendezvousIdentityV3 {
        bootstrap: options.bootstraps[0],
        key: &key,
        authority: &pin,
    };
    assert!(
        catch_unwind(AssertUnwindSafe(|| serve_authenticated_cell_rendezvous_pq(
            &listener,
            &directory,
            &options.addresses,
            &identity,
            &AtomicBool::new(false),
            CellRendezvousLimitsV2 {
                request_timeout: Duration::from_secs(2),
                lifetime: Duration::MAX,
                max_connections: 1
            }
        )))
        .unwrap()
        .is_err()
    );
    assert!(!output.exists());
    assert_eq!(
        directory
            .usage_at(wall_now().unwrap().as_secs(), deadline())
            .unwrap()
            .retained_identities,
        0
    );
    assert!(matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}

fn expired_newest_sequence_case(newer_first: bool) {
    epoch_now();
    let (provider_key, provider_pin) = key_and_pin(41);
    let provider_keys = CellPqKeyPinsV2::new(vec![provider_pin]).unwrap();
    let newer_endpoint: SocketAddr = "127.0.0.1:19001".parse().unwrap();
    let older_endpoint: SocketAddr = "127.0.0.2:19001".parse().unwrap();
    let wall = wall_now().unwrap();
    let fractional = wall - Duration::from_secs(wall.as_secs());
    if fractional > Duration::from_millis(100) {
        thread::sleep(Duration::from_secs(1) - fractional);
    }
    let now = wall_now().unwrap().as_secs();
    let request = request([22; 32], now);
    let newer = CellProviderRecordV3::sign(
        CellProviderStatementV3 {
            request,
            owner: provider_key.public_key_id(),
            owner_generation: 1,
            endpoint: newer_endpoint,
            sequence: 2,
            issued_unix_seconds: now,
            expires_unix_seconds: now + 1,
            withdrawn: false,
        },
        &provider_key,
    )
    .unwrap();
    let older = record(request, older_endpoint, 1, now, &provider_key, false);
    let mut newer_body = vec![1];
    newer_body.extend(newer.encode());
    let mut older_body = vec![1];
    older_body.extend(older.encode());
    let (first_body, second_body) = if newer_first {
        (newer_body, older_body)
    } else {
        (older_body, newer_body)
    };
    let first = SignedSource::start(42, first_body, Duration::ZERO, 1);
    let second = SignedSource::start(43, second_body, Duration::ZERO, 1);
    // Both advertisements were received while the newer one was live. The
    // third source expires that lease before fair admission starts, within its
    // original two-second request and the operation's ten-second deadline.
    let slow = SignedSource::start(44, vec![0], Duration::from_millis(1_200), 1);
    let options = CellDiscoveryOptionsV3 {
        request,
        bootstraps: vec![first.bootstrap, second.bootstrap, slow.bootstrap],
        bootstrap_keys: CellPqKeyPinsV2::new(vec![
            first.authority.clone(),
            second.authority.clone(),
            slow.authority.clone(),
        ])
        .unwrap(),
        addresses: policy(&[
            newer_endpoint,
            older_endpoint,
            first.bootstrap.endpoint,
            second.bootstrap.endpoint,
            slow.bootstrap.endpoint,
        ]),
    };
    let tmp = tempfile::tempdir().unwrap();
    let directory = CellProviderDirectoryV3::open(
        &tmp.path().join("directory"),
        context(),
        provider_keys,
        options.source_pins().unwrap(),
    )
    .unwrap();
    let attempts = AtomicU64::new(3);
    let bytes = (3 * (RESPONSE_HEADER_BYTES + 1 + ML_DSA_65_SIGNATURE_BYTES)
        + 2 * CELL_PROVIDER_RECORD_BYTES_V3) as u64;
    let responses = ResponseBudget::new(bytes);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: deadline(),
        requests_left: &attempts,
        responses: &responses,
    };
    let mut observation = CellDiscoveryObservationV3::default();
    let result = discover(&directory, &options, &transport, &mut observation);
    assert_eq!(observation.connection_attempts, 3);
    assert_eq!(observation.bootstrap_validation_attempts, 3);
    assert_eq!(observation.record_validation_attempts, 2);
    assert_eq!(observation.signature_attempts(), 5);
    assert_eq!(observation.received_response_bytes, bytes);
    assert_eq!(responses.received().unwrap(), bytes);
    assert_eq!(attempts.load(Ordering::Relaxed), 0);
    assert!(wall_now().unwrap().as_secs() >= newer.statement().expires_unix_seconds);
    assert_eq!(first.finish().len(), 1);
    assert_eq!(second.finish().len(), 1);
    assert_eq!(slow.finish().len(), 1);
    assert!(
        result.is_err(),
        "expired newer signed sequence resurrected an older provider: {:?}",
        result.as_ref().map(|(peers, _)| peers)
    );
    // A lower row committed before the higher observation is not erased or
    // relabeled as a durable higher sequence. It is simply ineligible here.
    let current = directory
        .records(request, wall_now().unwrap().as_secs(), deadline())
        .unwrap();
    assert_eq!(current.len(), usize::from(!newer_first));
    if !newer_first {
        assert_eq!(current[0].statement().sequence, 1);
    }
}

#[test]
fn authenticated_v3_newest_verified_expired_high_first_vetoes_later_low_sequence() {
    expired_newest_sequence_case(true);
}

#[test]
fn authenticated_v3_newest_verified_expired_high_later_removes_observed_low_sequence() {
    expired_newest_sequence_case(false);
}

#[test]
fn authenticated_v3_newest_verified_quota_rejected_withdrawal_vetoes_older_source() {
    let now = epoch_now();
    let tmp = tempfile::tempdir().unwrap();
    let endpoint: SocketAddr = "127.0.0.1:19001".parse().unwrap();
    let request = request([23; 32], now);
    let history_keys: Vec<_> = (1..=8).map(key_and_pin).collect();
    let (provider_key, provider_pin) = key_and_pin(41);
    let mut pins: Vec<_> = history_keys.iter().map(|(_, pin)| pin.clone()).collect();
    pins.push(provider_pin);
    let provider_keys = CellPqKeyPinsV2::new(pins).unwrap();
    let mut history_body = vec![8];
    for (key, _) in &history_keys {
        history_body.extend(record(request, endpoint, 1, now, key, true).encode());
    }
    let newer = record(request, endpoint, 2, now, &provider_key, true);
    let older = record(request, endpoint, 1, now, &provider_key, false);
    let mut newer_body = vec![1];
    newer_body.extend(newer.encode());
    let mut older_body = vec![1];
    older_body.extend(older.encode());
    let first = SignedSource::start_sequence(42, vec![history_body, newer_body], Duration::ZERO);
    let second = SignedSource::start_sequence(43, vec![vec![0], older_body], Duration::ZERO);
    let options = CellDiscoveryOptionsV3 {
        request,
        bootstraps: vec![first.bootstrap, second.bootstrap],
        bootstrap_keys: CellPqKeyPinsV2::new(vec![
            first.authority.clone(),
            second.authority.clone(),
        ])
        .unwrap(),
        addresses: policy(&[
            endpoint,
            first.bootstrap.endpoint,
            second.bootstrap.endpoint,
        ]),
    };
    let directory = CellProviderDirectoryV3::open(
        &tmp.path().join("directory"),
        context(),
        provider_keys,
        options.source_pins().unwrap(),
    )
    .unwrap();
    // A distinct earlier, real TCP operation fills this source's eight retained
    // per-manifest slots with signed inactive withdrawals. The directory and
    // source roster persist unchanged into the next operation.
    let preparation_attempts = AtomicU64::new(2);
    let preparation_bytes = (2 * (RESPONSE_HEADER_BYTES + 1 + ML_DSA_65_SIGNATURE_BYTES)
        + 8 * CELL_PROVIDER_RECORD_BYTES_V3) as u64;
    let preparation_responses = ResponseBudget::new(preparation_bytes);
    let preparation_transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: deadline(),
        requests_left: &preparation_attempts,
        responses: &preparation_responses,
    };
    let mut preparation = CellDiscoveryObservationV3::default();
    assert!(matches!(
        discover(
            &directory,
            &options,
            &preparation_transport,
            &mut preparation
        ),
        Err(CellErrorV1::Invalid(
            "authenticated discovery has no admissible provider"
        ))
    ));
    assert_eq!(preparation.connection_attempts, 2);
    assert_eq!(preparation.signature_attempts(), 10);
    assert_eq!(preparation.record_validation_attempts, 8);
    assert_eq!(preparation.capacity_rejections, 0);
    assert_eq!(preparation.received_response_bytes, preparation_bytes);
    assert_eq!(preparation_responses.received().unwrap(), preparation_bytes);
    assert_eq!(preparation_attempts.load(Ordering::Relaxed), 0);
    let usage = directory
        .usage_at(wall_now().unwrap().as_secs(), deadline())
        .unwrap();
    assert_eq!(usage.retained_identities, 8);
    assert_eq!(usage.active_identities, 0);

    let attempts = AtomicU64::new(2);
    let bytes = 2
        * (RESPONSE_HEADER_BYTES + 1 + CELL_PROVIDER_RECORD_BYTES_V3 + ML_DSA_65_SIGNATURE_BYTES)
            as u64;
    let responses = ResponseBudget::new(bytes);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: deadline(),
        requests_left: &attempts,
        responses: &responses,
    };
    let mut observation = CellDiscoveryObservationV3::default();
    let result = discover(&directory, &options, &transport, &mut observation);
    assert_eq!(observation.connection_attempts, 2);
    assert_eq!(observation.bootstrap_validation_attempts, 2);
    assert_eq!(observation.record_validation_attempts, 2);
    assert_eq!(observation.signature_attempts(), 4);
    assert_eq!(observation.capacity_rejections, 1);
    assert_eq!(observation.received_response_bytes, bytes);
    assert_eq!(responses.received().unwrap(), bytes);
    assert_eq!(attempts.load(Ordering::Relaxed), 0);
    assert_eq!(first.finish().len(), 2);
    assert_eq!(second.finish().len(), 2);
    assert!(
        result.is_err(),
        "a quota-refused newer withdrawal allowed an older source: {:?}",
        result.as_ref().map(|(peers, _)| peers)
    );
    let current = directory
        .records(request, wall_now().unwrap().as_secs(), deadline())
        .unwrap();
    assert_eq!(current.len(), 8);
    assert!(current
        .iter()
        .all(|record| record.statement().owner != provider_key.public_key_id()));
}
