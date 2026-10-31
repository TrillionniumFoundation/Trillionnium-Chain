use super::*;
use crate::cell::{
    network::{RequestContext, ResponseBudget},
    pq::CellPqKeyPinV2,
    serve_cells, CellCacheConfigV4, CellContextV1, CellPeerLimitsV1, CellStoreV1,
};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
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
        family: "pq-discovery".into(),
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
fn key_and_pin() -> (PqNativeSigningKey, CellPqKeyPinV2) {
    let seed = Zeroizing::new([42; 32]);
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
    CellPqKeyPinsV2::new(vec![key_and_pin().1]).unwrap()
}
fn record(
    request: CellDiscoveryRequestV1,
    endpoint: SocketAddr,
    sequence: u64,
    now: u64,
    withdrawn: bool,
) -> CellProviderRecordV2 {
    let (key, pin) = key_and_pin();
    CellProviderRecordV2::sign(
        CellProviderStatementV2 {
            request,
            owner: pin.key_id,
            owner_generation: 1,
            endpoint,
            sequence,
            issued_unix_seconds: now.saturating_sub(1),
            expires_unix_seconds: now + 240,
            withdrawn,
        },
        &key,
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

#[test]
fn actual_mldsa_record_rejects_every_changed_field_classic_and_trailing_wire() {
    let request = request([10; 32]);
    let endpoint = "127.0.0.1:19001".parse().unwrap();
    let policy = policy(&[endpoint]);
    let record = record(request, endpoint, 1, 100, false);
    let keys = keys();
    let wire = record.encode();
    assert_eq!(wire.len(), 3592);
    assert_eq!(record.verify_at(request, 100, &policy, &keys).unwrap(), 340);
    for index in 0..283 {
        let mut changed = wire.clone();
        changed[index] ^= 1;
        assert!(
            CellProviderRecordV2::decode(&changed)
                .and_then(|v| v.verify_at(request, 100, &policy, &keys))
                .is_err(),
            "accepted byte {index}"
        );
    }
    for index in [283, 500, 3591] {
        let mut changed = wire.clone();
        changed[index] ^= 1;
        assert!(CellProviderRecordV2::decode(&changed)
            .unwrap()
            .verify_at(request, 100, &policy, &keys)
            .is_err());
    }
    for size in [0, 335, 3591, 3593] {
        let mut changed = wire.clone();
        changed.resize(size, 0);
        assert!(CellProviderRecordV2::decode(&changed).is_err());
    }
    assert!(super::super::CellProviderRecordV1::decode(&wire).is_err());
    assert!(record.verify_at(request, 340, &policy, &keys).is_err());
    let mut pin = key_and_pin().1;
    pin.revoked_at = Some(101);
    let revoked = CellPqKeyPinsV2::new(vec![pin]).unwrap();
    assert_eq!(
        record.verify_at(request, 100, &policy, &revoked).unwrap(),
        101
    );
    assert!(record.verify_at(request, 101, &policy, &revoked).is_err());
}

#[test]
fn randomized_signatures_preserve_semantic_high_water_and_original_durable_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("directory");
    let endpoint = "127.0.0.1:19001".parse().unwrap();
    let request = request([10; 32]);
    let directory = CellProviderDirectoryV2::open(&path, context(), keys()).unwrap();
    // The durable clock is initialized during open; select a valid event
    // timestamp afterward, including when initialization crosses a second.
    let now = wall_now().unwrap().as_secs();
    let first = record(request, endpoint, 1, now, false);
    let mut second = first.clone();
    // FIPS204 pure prefix (0,empty-context-length) with independent nonzero rnd.
    // This is a test of randomized wire equivalence, not a runtime fallback.
    let seed = ml_dsa::Seed::from([42; 32]);
    let key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
    let message = first.message();
    let signature = key
        .expanded_key()
        .sign_internal(&[&[0, 0], &message], &[99; 32].into());
    second.signature.copy_from_slice(&signature.encode());
    assert_ne!(first.encode(), second.encode());
    assert_eq!(first, second);
    assert_eq!(first.digest(), second.digest());
    for candidate in [&first, &second] {
        candidate
            .verify_at(request, now, &policy(&[endpoint]), directory.keys())
            .unwrap();
        directory
            .accept_verified(candidate, endpoint.ip(), now, deadline())
            .unwrap();
    }
    assert_eq!(
        directory.records(request, now, deadline()).unwrap()[0].encode(),
        first.encode()
    );
    assert_eq!(directory.usage().unwrap().retained_wire_bytes, 3592);
    let mut statement = first.statement.clone();
    statement.expires_unix_seconds -= 1;
    let conflict = CellProviderRecordV2::sign(statement, &key_and_pin().0).unwrap();
    conflict
        .verify_at(request, now, &policy(&[endpoint]), directory.keys())
        .unwrap();
    assert!(directory
        .accept_verified(&conflict, endpoint.ip(), now, deadline())
        .is_err());
}

#[test]
fn fresh_schema_commits_key_roster_and_never_rewinds_with_expiry_or_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("directory");
    // Fresh open seals the durable initial clock using wall_now(); choose
    // the test's publication time afterwards so a second rollover during
    // SQLite creation is never mistaken for an attempted database rollback.
    let directory = CellProviderDirectoryV2::open(&path, context(), keys()).unwrap();
    let now = wall_now().unwrap().as_secs();
    let endpoint = "127.0.0.1:19001".parse().unwrap();
    let request = request([10; 32]);
    let first = record(request, endpoint, 1, now, false);
    let withdrawal = record(request, endpoint, 2, now, true);
    for candidate in [&first, &withdrawal] {
        candidate
            .verify_at(request, now, &policy(&[endpoint]), directory.keys())
            .unwrap();
        directory
            .accept_verified(candidate, endpoint.ip(), now, deadline())
            .unwrap();
    }
    assert!(directory
        .accept_verified(&first, endpoint.ip(), now, deadline())
        .is_err());
    drop(directory);
    assert!(super::super::CellProviderDirectoryV1::open(&path, context()).is_err());
    let mut changed = key_and_pin().1;
    changed.revoked_at = Some(now + 100);
    assert!(CellProviderDirectoryV2::open(
        &path,
        context(),
        CellPqKeyPinsV2::new(vec![changed]).unwrap()
    )
    .is_err());
    let directory = CellProviderDirectoryV2::open(&path, context(), keys()).unwrap();
    let rows = directory.records(request, now + 250, deadline()).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].statement.withdrawn);
    assert_eq!(rows[0].statement.sequence, 2);
    assert_eq!(directory.usage().unwrap().retained_identities, 1);
    assert!(directory.records(request, now, deadline()).is_err());
    drop(directory);
    let directory = CellProviderDirectoryV2::open(&path, context(), keys()).unwrap();
    assert!(directory.records(request, now, deadline()).is_err());
}

#[test]
fn cpk2_roster_wire_is_canonical_and_revocation_bound() {
    let keys = keys();
    let wire = keys.encode();
    assert_eq!(wire.len(), 2047);
    let decoded = CellPqKeyPinsV2::decode(&wire).unwrap();
    assert_eq!(decoded.digest(), keys.digest());
    for i in [0, 4, 5, 6, 7, 8, 48] {
        let mut changed = wire.clone();
        changed[i] ^= 1;
        assert!(CellPqKeyPinsV2::decode(&changed).is_err());
    }
    let mut changed = wire.clone();
    changed.push(0);
    assert!(CellPqKeyPinsV2::decode(&changed).is_err());
    let mut changed = wire;
    let n = changed.len();
    changed[n - 1] = 1;
    assert!(CellPqKeyPinsV2::decode(&changed).is_err());
}

#[test]
fn invalid_signatures_consume_server_slots_without_publication() {
    let tmp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint = "127.0.0.1:19001".parse().unwrap();
    let addresses = policy(&[address, endpoint]);
    let directory = Arc::new(
        CellProviderDirectoryV2::open(&tmp.path().join("directory"), context(), keys()).unwrap(),
    );
    let worker = Arc::clone(&directory);
    let handle = thread::spawn(move || {
        serve_cell_rendezvous_pq(
            &listener,
            &worker,
            &addresses,
            &AtomicBool::new(false),
            CellRendezvousLimitsV2 {
                request_timeout: Duration::from_secs(2),
                lifetime: Duration::from_secs(15),
                max_connections: 64,
            },
        )
        .unwrap()
    });
    let now = wall_now().unwrap().as_secs();
    let mut bad = record(request([10; 32]), endpoint, 1, now, false).encode();
    bad[500] ^= 1;
    for _ in 0..64 {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut header = b"CDQ2".to_vec();
        header.push(2);
        header.extend((bad.len() as u16).to_be_bytes());
        stream.write_all(&header).unwrap();
        stream.write_all(&bad).unwrap();
        let mut reply = [0; 9];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..4], b"CDS2");
        assert_eq!(reply[4], 1);
    }
    let report = handle.join().unwrap();
    assert_eq!(report.connections, 64);
    assert_eq!(report.record_validation_attempts, 64);
    assert_eq!(report.rejected_requests, 64);
    assert_eq!(directory.usage().unwrap().retained_identities, 0);
}

#[test]
fn real_tcp_pq_discovery_fetch_and_withdrawal_share_persisted_high_water_and_budget() {
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
    let rendezvous_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let rendezvous = rendezvous_listener.local_addr().unwrap();
    let addresses = policy(&[data, rendezvous]);
    let directory =
        CellProviderDirectoryV2::open(&tmp.path().join("rendezvous"), context(), keys()).unwrap();
    let server_policy = addresses.clone();
    let shutdown = Arc::clone(&stop);
    let rendezvous_worker = thread::spawn(move || {
        serve_cell_rendezvous_pq(
            &rendezvous_listener,
            &directory,
            &server_policy,
            &shutdown,
            CellRendezvousLimitsV2 {
                request_timeout: Duration::from_secs(2),
                lifetime: Duration::from_secs(15),
                max_connections: 64,
            },
        )
        .unwrap()
    });
    let request = request(manifest.id());
    let now = wall_now().unwrap().as_secs();
    let advert = record(request, data, 1, now, false);
    announce_cell_provider_pq(
        &advert,
        rendezvous,
        &keys(),
        &addresses,
        limits(),
        deadline(),
    )
    .unwrap();
    let client =
        CellProviderDirectoryV2::open(&tmp.path().join("client-directory"), context(), keys())
            .unwrap();
    let store = CellStoreV1::open(&tmp.path().join("client-cache"), cache()).unwrap();
    let options = CellDiscoveryOptionsV2 {
        request,
        bootstraps: vec![rendezvous],
        addresses: addresses.clone(),
    };
    let output = tmp.path().join("output");
    let (_, report) =
        fetch_discovered_cell_to_file_pq(&store, &client, &options, limits(), deadline(), &output)
            .unwrap();
    assert_eq!(fs::read(&output).unwrap(), bytes);
    assert_eq!(report.discovered_providers, vec![data]);
    assert_eq!(report.discovery.record_validation_attempts, 1);
    assert!(report.fetch.received_response_bytes >= report.discovery.received_response_bytes);
    assert!(report.fetch.connection_attempts > report.discovery.connection_attempts);
    let withdrawal = record(request, data, 2, wall_now().unwrap().as_secs(), true);
    announce_cell_provider_pq(
        &withdrawal,
        rendezvous,
        &keys(),
        &addresses,
        limits(),
        deadline(),
    )
    .unwrap();
    let blocked = tmp.path().join("blocked");
    assert!(fetch_discovered_cell_to_file_pq(
        &store,
        &client,
        &options,
        limits(),
        deadline(),
        &blocked
    )
    .is_err());
    assert!(!blocked.exists());
    assert!(announce_cell_provider_pq(
        &advert,
        rendezvous,
        &keys(),
        &addresses,
        limits(),
        deadline()
    )
    .is_err());
    let current = client
        .records(request, wall_now().unwrap().as_secs(), deadline())
        .unwrap();
    assert!(current[0].statement.withdrawn);
    // A response-byte reservation too small for even the header is charged and
    // never refreshed to obtain a second, larger allowance in this operation.
    let attempts = AtomicU64::new(2);
    let responses = ResponseBudget::new(8);
    let transport = RequestContext {
        timeout: Duration::from_secs(2),
        overall: deadline(),
        requests_left: &attempts,
        responses: &responses,
    };
    let mut observation = CellDiscoveryObservationV2::default();
    assert!(transport::discover(&client, &options, &transport, &mut observation).is_err());
    assert_eq!(responses.received().unwrap(), 8);
    stop.store(true, Ordering::Relaxed);
    data_worker.join().unwrap();
    rendezvous_worker.join().unwrap();
}
