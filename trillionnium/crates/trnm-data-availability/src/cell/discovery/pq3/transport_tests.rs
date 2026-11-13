use super::auth::{BootstrapQueryV3, RESPONSE_HEADER_BYTES, RESPONSE_OVERHEAD};
use super::*;
use crate::cell::{
    network::{RequestContext, ResponseBudget},
    pq::CellPqKeyPinV2,
    serve_cells, CellCacheConfigV4, CellContextV1, CellPeerLimitsV1, CellStoreV1,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
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
        family: "pq-discovery-v3".into(),
        base: [5; 32],
        parent: [6; 32],
        tokenizer: [7; 32],
        layout: [8; 32],
        runtime: [9; 32],
    }
}
fn request(manifest: CellDigestV1) -> CellDiscoveryRequestV1 {
    CellDiscoveryRequestV1 {
        context: context(),
        cell_context: cell_discovery_context_digest(&cell_context()).unwrap(),
        manifest,
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
fn keys() -> CellPqKeyPinsV2 {
    CellPqKeyPinsV2::new(vec![key_and_pin(42).1]).unwrap()
}
fn signer(seed: u8, endpoint: SocketAddr) -> (CellBootstrapSignerV3, CellPqKeyPinV2) {
    let (key, key_pin) = key_and_pin(seed);
    let pin = CellBootstrapPinV3 {
        endpoint,
        key_id: key_pin.key_id,
        generation: key_pin.generation,
    };
    (
        CellBootstrapSignerV3::new(
            pin,
            key,
            CellPqKeyPinsV2::new(vec![key_pin.clone()]).unwrap(),
        )
        .unwrap(),
        key_pin,
    )
}
fn record(
    request: CellDiscoveryRequestV1,
    endpoint: SocketAddr,
    sequence: u64,
    now: u64,
    withdrawn: bool,
) -> CellProviderRecordV3 {
    let (key, pin) = key_and_pin(42);
    signed_record(request, endpoint, sequence, now, withdrawn, &key, &pin)
}
fn signed_record(
    request: CellDiscoveryRequestV1,
    endpoint: SocketAddr,
    sequence: u64,
    now: u64,
    withdrawn: bool,
    key: &PqNativeSigningKey,
    pin: &CellPqKeyPinV2,
) -> CellProviderRecordV3 {
    let epoch = now / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3;
    CellProviderRecordV3::sign(
        CellProviderStatementV3 {
            request,
            owner: pin.key_id,
            owner_generation: pin.generation,
            endpoint,
            sequence,
            lease_epoch: epoch,
            issued_unix_seconds: now,
            expires_unix_seconds: (now + 240)
                .min((epoch + 1) * CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3),
            withdrawn,
        },
        key,
    )
    .unwrap()
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
fn live_now() -> u64 {
    let now = wall_now().unwrap().as_secs();
    let left = 300 - now % 300;
    // Only test fixture preparation waits; an operation never renews its epoch.
    if left < 8 {
        thread::sleep(Duration::from_secs(left) + Duration::from_millis(20));
    }
    wall_now().unwrap().as_secs()
}
fn read_query(stream: &mut std::net::TcpStream) -> BootstrapQueryV3 {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut header = [0; auth::QUERY_HEADER_BYTES];
    stream.read_exact(&mut header).unwrap();
    let length = auth::query_length(&header).unwrap();
    let mut wire = header.to_vec();
    wire.resize(header.len() + length, 0);
    stream.read_exact(&mut wire[header.len()..]).unwrap();
    BootstrapQueryV3::decode(&wire).unwrap()
}

#[test]
fn native_response_binds_complete_query_nonce_target_result_status_and_lifetime() {
    let endpoint = "127.0.0.1:19010".parse().unwrap();
    let (signer, pin) = signer(92, endpoint);
    let keys = CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap();
    let now = wall_now().unwrap().as_secs();
    let query = BootstrapQueryV3::fresh(1, signer.identity(), &request([10; 32]).encode()).unwrap();
    let wire = signer.sign_response(&query, 0, &[0], now).unwrap();
    assert_eq!(wire.len(), RESPONSE_OVERHEAD + 1);
    assert_eq!(
        auth::verify_response(&query, &wire, 1, now, &keys)
            .unwrap()
            .body,
        [0]
    );
    let mut nonces = BTreeSet::new();
    nonces.insert(query.nonce);
    for _ in 0..32 {
        let retry = BootstrapQueryV3::fresh(1, signer.identity(), &query.body).unwrap();
        assert!(nonces.insert(retry.nonce));
        assert!(auth::verify_response(&retry, &wire, 1, now, &keys).is_err());
    }
    // Every request component remains bound even when nonce and source key match.
    for at in [0, 32, 64, 96, 128, 160] {
        let mut changed = BootstrapQueryV3::decode(&query.encode()).unwrap();
        changed.body[at] ^= 7;
        assert!(auth::verify_response(&changed, &wire, 1, now, &keys).is_err());
    }
    let mut changed = BootstrapQueryV3::decode(&query.encode()).unwrap();
    changed.pin.endpoint.set_port(19011);
    assert!(auth::verify_response(&changed, &wire, 1, now, &keys).is_err());
    changed = BootstrapQueryV3::decode(&query.encode()).unwrap();
    changed.pin.generation += 1;
    assert!(auth::verify_response(&changed, &wire, 1, now, &keys).is_err());
    changed = BootstrapQueryV3::decode(&query.encode()).unwrap();
    changed.kind = 2;
    assert!(auth::verify_response(&changed, &wire, 1, now, &keys).is_err());
    for at in [0, 4, 5, 6, 10, 11, 43, 75, 83, 91, 99, 100, wire.len() - 1] {
        let mut modified = wire.clone();
        modified[at] ^= 1;
        assert!(
            auth::verify_response(&query, &modified, 1, now, &keys).is_err(),
            "byte {at}"
        );
    }
    assert!(auth::verify_response(&query, &wire, 1, now + 30, &keys).is_err());
    let future = signer.sign_response(&query, 0, &[0], now + 6).unwrap();
    assert!(auth::verify_response(&query, &future, 1, now, &keys).is_err());
    let mut revoked = pin.clone();
    revoked.revoked_at = Some(now);
    let revoked = CellPqKeyPinsV2::new(vec![revoked]).unwrap();
    assert!(auth::verify_response(&query, &wire, 1, now, &revoked).is_err());
    let unrelated = CellPqKeyPinsV2::new(vec![key_and_pin(93).1]).unwrap();
    assert!(auth::verify_response(&query, &wire, 1, now, &unrelated).is_err());
    let denial = signer.sign_response(&query, 2, &[], now).unwrap();
    assert_eq!(
        auth::verify_response(&query, &denial, 1, now, &keys)
            .unwrap()
            .status,
        2
    );
    assert!(signer.sign_response(&query, 0, &[], now).is_err());
    assert!(signer.sign_response(&query, 2, &[1], now).is_err());
    let mut old = wire.clone();
    old[..6].copy_from_slice(&[b'C', b'D', b'S', b'2', 2, 0x65]);
    assert!(auth::verify_response(&query, &old, 1, now, &keys).is_err());
    assert!(auth::verify_response(&query, &wire[..wire.len() - 1], 1, now, &keys).is_err());
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(auth::verify_response(&query, &trailing, 1, now, &keys).is_err());
}

#[test]
fn maximum_signed_result_fits_original_byte_cap_and_binds_last_record() {
    let endpoint = "127.0.0.1:19010".parse().unwrap();
    let (signer, keypin) = signer(92, endpoint);
    let keys = CellPqKeyPinsV2::new(vec![keypin]).unwrap();
    let now = wall_now().unwrap().as_secs();
    let request = request([10; 32]);
    let record = record(request, endpoint, 1, now, false);
    let query = BootstrapQueryV3::fresh(1, signer.identity(), &request.encode()).unwrap();
    let mut body = vec![8];
    for _ in 0..8 {
        body.extend(record.encode());
    }
    let wire = signer.sign_response(&query, 0, &body, now).unwrap();
    assert!(
        wire.len() * MAX_DISCOVERY_CONNECTIONS as usize <= MAX_DISCOVERY_RESPONSE_BYTES_V3 as usize
    );
    assert_eq!(
        auth::verify_response(&query, &wire, auth::MAX_REPLY_BYTES, now, &keys)
            .unwrap()
            .body,
        body
    );
    let mut changed = wire.clone();
    changed[wire.len() - ML_DSA_65_SIGNATURE_BYTES - 1] ^= 1;
    assert!(auth::verify_response(&query, &changed, auth::MAX_REPLY_BYTES, now, &keys).is_err());
    let mut oversized = wire[..RESPONSE_HEADER_BYTES].to_vec();
    oversized[7..11].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(auth::response_length(&oversized, auth::MAX_REPLY_BYTES).is_err());
}

#[test]
fn epoch_rollover_resets_sequence_without_reusing_old_sources_or_expiry() {
    let req = request([10; 32]);
    let endpoint = "127.0.0.1:19010".parse().unwrap();
    let old = record(req, endpoint, 100, 599, false);
    let new = record(req, endpoint, 1, 600, false);
    let mut conflicting_old = old.statement.clone();
    conflicting_old.withdrawn = true;
    let conflicting_old = CellProviderRecordV3::sign(conflicting_old, &key_and_pin(42).0).unwrap();
    let mut history = BTreeMap::new();
    let mut equivocated = BTreeSet::new();
    let mut observed = BTreeMap::new();
    let old_expiry = Instant::now() + Duration::from_secs(1);
    let new_expiry = Instant::now() + Duration::from_secs(20);
    assert!(transport::remember_verified_statement(
        &mut history,
        &mut equivocated,
        &mut observed,
        &old
    )
    .unwrap());
    assert!(transport::retain_observed(&mut observed, old.clone(), old_expiry, 600, 1).unwrap());
    assert!(transport::remember_verified_statement(
        &mut history,
        &mut equivocated,
        &mut observed,
        &new
    )
    .unwrap());
    assert!(transport::retain_observed(&mut observed, new.clone(), new_expiry, 620, 2).unwrap());
    assert!(!transport::remember_verified_statement(
        &mut history,
        &mut equivocated,
        &mut observed,
        &conflicting_old
    )
    .unwrap());
    let current = observed.get(&new.statement.owner).unwrap();
    assert_eq!(current.record, new);
    assert_eq!(current.sources, 2);
    assert_eq!(current.expires, new_expiry);
    assert!(!transport::retain_observed(&mut observed, old, old_expiry, 600, 1).unwrap());
    assert!(transport::retain_observed(
        &mut observed,
        new.clone(),
        new_expiry + Duration::from_secs(5),
        625,
        4
    )
    .unwrap());
    let current = observed.get(&new.statement.owner).unwrap();
    assert_eq!(current.sources, 6);
    assert_eq!(current.expires, new_expiry);
    assert_eq!(current.expires_unix_seconds, 620);
    assert!(!equivocated.contains(&(new.statement.owner, new.statement.lease_epoch)));
}

#[test]
fn real_tcp_authenticated_announce_cold_fetch_withdrawal_and_failed_denominators() {
    let now = live_now();
    let tmp = tempfile::tempdir().unwrap();
    let origin_path = tmp.path().join("origin");
    let origin = CellStoreV1::open(&origin_path, cache()).unwrap();
    let input = tmp.path().join("input");
    let bytes = vec![37; 40_000];
    fs::write(&input, &bytes).unwrap();
    let manifest = origin.pack_file(&input, cell_context(), 16_384).unwrap();
    drop(origin);
    let data_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let data = data_listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::clone(&stop);
    let data_worker = thread::spawn(move || {
        let store = CellStoreV1::open(&origin_path, cache()).unwrap();
        serve_cells(&data_listener, &store, &shutdown, limits()).unwrap()
    });
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let rendezvous = listener.local_addr().unwrap();
    let addresses = policy(&[data, rendezvous]);
    let (signer, keypin) = signer(92, rendezvous);
    let bootstrap = signer.identity();
    let directory =
        CellProviderDirectoryV3::open(&tmp.path().join("rendezvous"), context(), keys()).unwrap();
    let server_policy = addresses.clone();
    let shutdown = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        serve_cell_rendezvous_pq_v3(
            &listener,
            &directory,
            &signer,
            &server_policy,
            &shutdown,
            CellRendezvousLimitsV3 {
                request_timeout: Duration::from_secs(2),
                lifetime: Duration::from_secs(15),
                max_connections: 64,
            },
        )
        .unwrap()
    });
    let request = request(manifest.id());
    let advert = record(request, data, 1, now, false);
    let options = CellDiscoveryOptionsV3 {
        request,
        bootstraps: vec![bootstrap],
        bootstrap_keys: CellPqKeyPinsV2::new(vec![keypin]).unwrap(),
        addresses: addresses.clone(),
    };
    let ack =
        announce_cell_provider_pq_v3(&advert, 0, &keys(), &options, limits(), deadline()).unwrap();
    assert_eq!(ack.bootstrap_validation_attempts, 1);
    assert_eq!(ack.authenticated_bootstrap_responses, 1);
    assert_eq!(ack.received_response_bytes, (RESPONSE_OVERHEAD + 32) as u64);
    let client =
        CellProviderDirectoryV3::open(&tmp.path().join("client-directory"), context(), keys())
            .unwrap();
    let store = CellStoreV1::open(&tmp.path().join("client-cache"), cache()).unwrap();
    let output = tmp.path().join("output");
    let (_, report) = fetch_discovered_cell_to_file_pq_v3(
        &store,
        &client,
        &options,
        limits(),
        deadline(),
        &output,
    )
    .unwrap();
    assert_eq!(fs::read(&output).unwrap(), bytes);
    assert_eq!(report.discovered_providers, vec![data]);
    assert_eq!(report.discovery.record_validation_attempts, 1);
    assert_eq!(report.discovery.bootstrap_validation_attempts, 1);
    assert!(!report.manifest_initial_cache_hit);
    assert!(report.fetch.received_response_bytes > report.discovery.received_response_bytes);
    assert!(report.fetch.connection_attempts > report.discovery.connection_attempts);
    let withdrawal = record(request, data, 2, wall_now().unwrap().as_secs(), true);
    announce_cell_provider_pq_v3(&withdrawal, 0, &keys(), &options, limits(), deadline()).unwrap();
    let blocked = tmp.path().join("blocked");
    let failed = fetch_discovered_cell_to_file_pq_v3(
        &store,
        &client,
        &options,
        limits(),
        deadline(),
        &blocked,
    )
    .unwrap_err();
    assert!(!blocked.exists());
    assert!(failed.discovery.connection_attempts > 0);
    assert_eq!(
        failed.total_connection_attempts,
        failed.discovery.connection_attempts
    );
    assert_eq!(
        failed.total_received_response_bytes,
        Some(failed.discovery.received_response_bytes)
    );
    let stale = announce_cell_provider_pq_v3(&advert, 0, &keys(), &options, limits(), deadline())
        .unwrap_err();
    assert_eq!(stale.discovery.connection_attempts, 1);
    assert_eq!(stale.discovery.rejected_bootstraps, 1);
    assert_eq!(stale.discovery.authenticated_bootstrap_responses, 1);
    stop.store(true, Ordering::Relaxed);
    data_worker.join().unwrap();
    let served = worker.join().unwrap();
    assert!(
        served.record_validation_attempts + 2 * served.response_signing_attempts
            <= MAX_DISCOVERY_RECORDS
    );
}

#[test]
fn real_tcp_replayed_and_unsigned_replies_keep_actual_failure_denominator() {
    let tmp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let (signer, keypin) = signer(92, endpoint);
    let bootstrap = signer.identity();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let first = read_query(&mut stream);
        let signed = signer
            .sign_response(&first, 0, &[0], wall_now().unwrap().as_secs())
            .unwrap();
        // Old unsigned wire cannot be interpreted as a signed v3 response.
        stream.write_all(b"CDS2\0\0\0\0\x01\0\0").unwrap();
        drop(stream);
        let (mut stream, _) = listener.accept().unwrap();
        let second = read_query(&mut stream);
        assert_ne!(first.nonce, second.nonce);
        stream.write_all(&signed).unwrap();
        signed.len()
    });
    let options = CellDiscoveryOptionsV3 {
        request: request([11; 32]),
        bootstraps: vec![bootstrap],
        bootstrap_keys: CellPqKeyPinsV2::new(vec![keypin]).unwrap(),
        addresses: policy(&[endpoint]),
    };
    let directory =
        CellProviderDirectoryV3::open(&tmp.path().join("directory"), context(), keys()).unwrap();
    let store = CellStoreV1::open(&tmp.path().join("store"), cache()).unwrap();
    let failure = fetch_discovered_cell_to_file_pq_v3(
        &store,
        &directory,
        &options,
        limits(),
        deadline(),
        &tmp.path().join("out"),
    )
    .unwrap_err();
    let signed_length = worker.join().unwrap();
    assert_eq!(failure.discovery.connection_attempts, 2);
    assert_eq!(failure.discovery.rejected_bootstraps, 2);
    assert_eq!(failure.discovery.authenticated_bootstrap_responses, 0);
    assert_eq!(failure.discovery.bootstrap_validation_attempts, 1);
    assert_eq!(
        failure.discovery.received_response_bytes,
        (RESPONSE_HEADER_BYTES + signed_length) as u64
    );
    assert_eq!(failure.total_connection_attempts, 2);
    assert_eq!(
        failure.total_received_response_bytes,
        Some(failure.discovery.received_response_bytes)
    );
}

#[test]
fn real_tcp_partial_byte_exhaustion_prevents_another_dial_and_deadline_is_original() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let (signer, keypin) = signer(92, endpoint);
    let bootstrap = signer.identity();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let query = read_query(&mut stream);
        let wire = signer
            .sign_response(&query, 0, &[0], wall_now().unwrap().as_secs())
            .unwrap();
        let _ = stream.write_all(&wire);
    });
    let keys = CellPqKeyPinsV2::new(vec![keypin]).unwrap();
    let requests = AtomicU64::new(2);
    let responses = ResponseBudget::new(10);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: deadline(),
        requests_left: &requests,
        responses: &responses,
    };
    let mut observed = CellDiscoveryObservationV3::default();
    assert!(transport::exchange(
        bootstrap,
        &keys,
        1,
        &request([11; 32]).encode(),
        1,
        &transport,
        &mut observed
    )
    .is_err());
    assert_eq!(observed.connection_attempts, 1);
    assert_eq!(observed.received_response_bytes, 10);
    assert_eq!(responses.received().unwrap(), 10);
    assert!(transport::exchange(
        bootstrap,
        &keys,
        1,
        &request([11; 32]).encode(),
        1,
        &transport,
        &mut observed
    )
    .is_err());
    assert_eq!(observed.connection_attempts, 1);
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    worker.join().unwrap();
    let requests = AtomicU64::new(2);
    let responses = ResponseBudget::new(100);
    let expired = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall: Instant::now(),
        requests_left: &requests,
        responses: &responses,
    };
    let mut observed = CellDiscoveryObservationV3::default();
    assert!(transport::exchange(
        bootstrap,
        &keys,
        1,
        &request([11; 32]).encode(),
        1,
        &expired,
        &mut observed
    )
    .is_err());
    assert_eq!(observed.connection_attempts, 0);
    assert_eq!(requests.load(Ordering::Relaxed), 2);
}

#[test]
fn real_tcp_failed_payload_retains_shared_session_connection_and_byte_totals() {
    let now = live_now();
    let tmp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let data_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let data = data_listener.local_addr().unwrap();
    let (signer, keypin) = signer(92, endpoint);
    let bootstrap = signer.identity();
    let request = request([11; 32]);
    let advert = record(request, data, 1, now, false);
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let query = read_query(&mut stream);
        let mut body = vec![1];
        body.extend(advert.encode());
        let wire = signer
            .sign_response(&query, 0, &body, wall_now().unwrap().as_secs())
            .unwrap();
        stream.write_all(&wire).unwrap();
    });
    let data_worker = thread::spawn(move || {
        for _ in 0..1 {
            let (mut stream, _) = data_listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = [0; 37];
            let _ = stream.read_exact(&mut request);
            let _ = stream.write_all(b"INVALID!!");
        }
    });
    let options = CellDiscoveryOptionsV3 {
        request,
        bootstraps: vec![bootstrap],
        bootstrap_keys: CellPqKeyPinsV2::new(vec![keypin]).unwrap(),
        addresses: policy(&[endpoint, data]),
    };
    let directory =
        CellProviderDirectoryV3::open(&tmp.path().join("directory"), context(), keys()).unwrap();
    let store = CellStoreV1::open(&tmp.path().join("store"), cache()).unwrap();
    let limits = CellPeerLimitsV1 {
        max_connections: 3,
        ..limits()
    };
    let failure = fetch_discovered_cell_to_file_pq_v3(
        &store,
        &directory,
        &options,
        limits,
        deadline(),
        &tmp.path().join("out"),
    )
    .unwrap_err();
    assert_eq!(failure.discovery.connection_attempts, 1);
    assert_eq!(failure.total_connection_attempts, 2);
    assert!(
        failure.total_received_response_bytes.unwrap() > failure.discovery.received_response_bytes
    );
    worker.join().unwrap();
    data_worker.join().unwrap();
}

#[test]
fn actual_server_bounds_signing_and_mandatory_self_verification_together() {
    let tmp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let (signer, keypin) = signer(92, endpoint);
    let bootstrap = signer.identity();
    let directory =
        CellProviderDirectoryV3::open(&tmp.path().join("directory"), context(), keys()).unwrap();
    let worker = thread::spawn(move || {
        serve_cell_rendezvous_pq_v3(
            &listener,
            &directory,
            &signer,
            &policy(&[endpoint]),
            &AtomicBool::new(false),
            CellRendezvousLimitsV3 {
                request_timeout: Duration::from_secs(2),
                lifetime: Duration::from_secs(20),
                max_connections: 64,
            },
        )
        .unwrap()
    });
    let keys = CellPqKeyPinsV2::new(vec![keypin]).unwrap();
    for _ in 0..32 {
        let requests = AtomicU64::new(1);
        let responses = ResponseBudget::new(10_000);
        let transport = RequestContext {
            cancelled: None,
            timeout: Duration::from_secs(2),
            overall: deadline(),
            requests_left: &requests,
            responses: &responses,
        };
        let mut observed = CellDiscoveryObservationV3::default();
        let reply = transport::exchange(
            bootstrap,
            &keys,
            1,
            &request([11; 32]).encode(),
            1,
            &transport,
            &mut observed,
        )
        .unwrap();
        assert_eq!(reply.body, [0]);
        assert_eq!(observed.bootstrap_validation_attempts, 1);
    }
    let report = worker.join().unwrap();
    assert_eq!(report.connections, 32);
    assert_eq!(report.record_validation_attempts, 0);
    assert_eq!(report.response_signing_attempts, 32);
    assert_eq!(report.rejected_requests, 0);
}

#[test]
fn duplicate_source_keys_and_wrong_generations_fail_before_connecting() {
    let tmp = tempfile::tempdir().unwrap();
    let one = "127.0.0.1:19010".parse().unwrap();
    let two = "127.0.0.1:19011".parse().unwrap();
    let (signer, keypin) = signer(92, one);
    let mut second = signer.identity();
    second.endpoint = two;
    let mut options = CellDiscoveryOptionsV3 {
        request: request([11; 32]),
        bootstraps: vec![signer.identity(), second],
        bootstrap_keys: CellPqKeyPinsV2::new(vec![keypin]).unwrap(),
        addresses: policy(&[one, two]),
    };
    let directory =
        CellProviderDirectoryV3::open(&tmp.path().join("directory"), context(), keys()).unwrap();
    let store = CellStoreV1::open(&tmp.path().join("store"), cache()).unwrap();
    let fail = fetch_discovered_cell_to_file_pq_v3(
        &store,
        &directory,
        &options,
        limits(),
        deadline(),
        &tmp.path().join("out"),
    )
    .unwrap_err();
    assert_eq!(fail.total_connection_attempts, 0);
    assert_eq!(fail.total_received_response_bytes, Some(0));
    options.bootstraps.remove(1);
    options.bootstraps[0].generation += 1;
    let fail = fetch_discovered_cell_to_file_pq_v3(
        &store,
        &directory,
        &options,
        limits(),
        deadline(),
        &tmp.path().join("out"),
    )
    .unwrap_err();
    assert_eq!(fail.total_connection_attempts, 0);
}
