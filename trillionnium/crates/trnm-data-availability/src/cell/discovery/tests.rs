use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
};

use super::super::network::{RequestContext, ResponseBudget};
use super::super::{fetch_cell, serve_cells, CellManifestV1, CellPeerLimitsV1, CellStoreV1};
use super::*;
use rusqlite::{params, Connection};

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
        family: "discovery-native-test-v1".into(),
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
fn key(index: u64) -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(index.to_be_bytes()).into())
}
fn policy(peers: &[SocketAddr]) -> CellDiscoveryAddressPolicyV1 {
    let mut ports: Vec<_> = peers.iter().map(SocketAddr::port).collect();
    ports.sort_unstable();
    ports.dedup();
    CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports }
}
fn record(
    pin: CellDiscoveryRequestV1,
    endpoint: SocketAddr,
    index: u64,
    sequence: u64,
    issued: u64,
) -> CellProviderRecordV1 {
    let key = key(index);
    CellProviderRecordV1::sign(
        CellProviderStatementV1 {
            request: pin,
            owner: key.verifying_key().to_bytes(),
            endpoint,
            sequence,
            issued_unix_seconds: issued,
            expires_unix_seconds: issued + MAX_TTL_SECONDS,
        },
        &key,
    )
    .unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn limits() -> CellPeerLimitsV1 {
    CellPeerLimitsV1 {
        request_timeout: Duration::from_millis(200),
        overall_timeout: Duration::from_secs(10),
        max_cell_bytes: 1_048_576,
        parallelism: 2,
        max_connections: 64,
        max_response_bytes: 4 * 1_048_576,
    }
}
fn accept(
    directory: &CellProviderDirectoryV1,
    value: &CellProviderRecordV1,
    source: IpAddr,
    now: u64,
) -> CellResultV1<()> {
    // Direct directory tests still use the real strict Ed25519 primitive. The
    // end-to-end discovery test below publishes through actual TCP instead.
    value.verify_signature()?;
    directory.accept_verified(value, source, now, deadline())
}
fn loopback() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

struct Peer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<CellResultV1<u64>>>,
}
impl Peer {
    fn start(path: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let path = path.to_owned();
        let handle = thread::spawn(move || {
            let store = CellStoreV1::open(&path, cache_config())?;
            serve_cells(&listener, &store, &stop, limits())
        });
        Self {
            address,
            shutdown,
            handle: Some(handle),
        }
    }
    fn stop(mut self) -> u64 {
        self.shutdown.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap().unwrap()
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
struct Rendezvous {
    address: SocketAddr,
    directory: Arc<CellProviderDirectoryV1>,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<CellResultV1<CellRendezvousReportV1>>>,
}
impl Rendezvous {
    fn start(path: &Path, providers: &[SocketAddr]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let addresses = policy(providers);
        let directory = Arc::new(CellProviderDirectoryV1::open(path, context()).unwrap());
        let owned = directory.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let handle = thread::spawn(move || {
            serve_cell_rendezvous(
                &listener,
                &owned,
                &addresses,
                &stop,
                CellRendezvousLimitsV1 {
                    request_timeout: Duration::from_millis(250),
                    lifetime: Duration::from_secs(30),
                    max_connections: 64,
                },
            )
        });
        Self {
            address,
            directory,
            shutdown,
            handle: Some(handle),
        }
    }
    fn stop(mut self) -> CellRendezvousReportV1 {
        self.shutdown.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap().unwrap()
    }
}
impl Drop for Rendezvous {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
fn fixture(path: &Path) -> (CellStoreV1, CellManifestV1, Vec<u8>, PathBuf) {
    let input = path.join("input");
    let bytes: Vec<_> = (0_u32..4097)
        .flat_map(|n| <[u8; 32]>::from(Sha256::digest(n.to_be_bytes())))
        .collect();
    fs::write(&input, &bytes).unwrap();
    let store_path = path.join("origin.sqlite");
    let store = CellStoreV1::open(&store_path, cache_config()).unwrap();
    let manifest = store.pack_file(&input, cell_context(), 16_384).unwrap();
    (store, manifest, bytes, store_path)
}
fn corrupt_chunk(path: &Path, manifest: &CellManifestV1) {
    let chunk = &manifest.chunks()[0];
    Connection::open(path)
        .unwrap()
        .execute(
            "UPDATE cell_chunks_v1 SET bytes=?1 WHERE hash=?2",
            params![vec![0_u8; chunk.size as usize], chunk.sha256.as_slice()],
        )
        .unwrap();
}

#[test]
fn tcp_bootstrap_discovers_unconfigured_providers_and_repairs_after_origin_exit() {
    let temp = tempfile::tempdir().unwrap();
    let (origin, manifest, bytes, origin_path) = fixture(temp.path());
    let publisher = Peer::start(&origin_path);
    let a_path = temp.path().join("a.sqlite");
    let b_path = temp.path().join("b.sqlite");
    for path in [&a_path, &b_path] {
        let replica = CellStoreV1::open(path, cache_config()).unwrap();
        let (received, report) =
            fetch_cell(&replica, manifest.id(), &[publisher.address], limits()).unwrap();
        assert_eq!(received, manifest);
        assert_eq!(report.downloaded_bytes, bytes.len() as u64);
    }
    let a = Peer::start(&a_path);
    let b = Peer::start(&b_path);
    let providers = [publisher.address, a.address, b.address];
    let bootstrap = Rendezvous::start(&temp.path().join("rendezvous.sqlite"), &providers);
    let failed = TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable = failed.local_addr().unwrap();
    let addresses = policy(&[
        providers[0],
        providers[1],
        providers[2],
        bootstrap.address,
        unavailable,
    ]);
    let pin = request(manifest.id());
    let now = wall_now().unwrap().as_secs();
    for (index, endpoint) in providers.iter().enumerate() {
        let value = record(pin, *endpoint, index as u64 + 1, 1, now);
        let published =
            announce_cell_provider(&value, bootstrap.address, &addresses, limits(), deadline())
                .unwrap();
        assert_eq!(published.connection_attempts, 1);
        assert_eq!(published.received_response_bytes, 41);
    }
    assert_eq!(bootstrap.directory.usage().unwrap().retained_identities, 3);
    drop(failed);
    publisher.stop();
    drop(origin);
    fs::remove_file(temp.path().join("input")).unwrap();
    fs::remove_file(origin_path).unwrap();
    corrupt_chunk(&a_path, &manifest);
    let consumer_path = temp.path().join("consumer.sqlite");
    let consumer = CellStoreV1::open(&consumer_path, cache_config()).unwrap();
    let directory =
        CellProviderDirectoryV1::open(&temp.path().join("client-directory.sqlite"), context())
            .unwrap();
    assert_eq!(directory.usage().unwrap().retained_identities, 0);
    // There are exactly two bootstrap addresses here and no provider list.
    let options = CellDiscoveryOptionsV1 {
        request: pin,
        bootstraps: vec![unavailable, bootstrap.address],
        addresses,
    };
    let output = temp.path().join("weights");
    let (received, report) = fetch_discovered_cell_to_file(
        &consumer,
        &directory,
        &options,
        limits(),
        deadline(),
        &output,
    )
    .unwrap();
    assert_eq!(received, manifest);
    assert_eq!(fs::read(&output).unwrap(), bytes);
    assert!(!report.manifest_initial_cache_hit);
    assert_eq!(directory.usage().unwrap().retained_identities, 3);
    assert_eq!(
        report
            .discovered_providers
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        providers.into_iter().collect()
    );
    assert_eq!(report.discovery.connection_attempts, 2);
    assert_eq!(report.discovery.rejected_bootstraps, 1);
    assert_eq!(report.discovery.record_validation_attempts, 3);
    assert_eq!(report.discovery.received_response_bytes, 9 + 1 + 3 * 335);
    assert_eq!(report.fetch.supplying_peers.len(), 2);
    assert!(
        report.fetch.received_response_bytes
            >= report.discovery.received_response_bytes + bytes.len() as u64
    );
    assert!(report.fetch.connection_attempts > report.discovery.connection_attempts);
    assert!(!report.fetch.supplying_peers.contains(&providers[0]));
    corrupt_chunk(&consumer_path, &manifest);
    let repaired = temp.path().join("repaired-weights");
    let (_, repair) = fetch_discovered_cell_to_file(
        &consumer,
        &directory,
        &options,
        limits(),
        deadline(),
        &repaired,
    )
    .unwrap();
    assert!(repair.manifest_initial_cache_hit);
    assert_eq!(repair.fetch.downloaded_chunks, 1);
    assert_eq!(fs::read(repaired).unwrap(), bytes);
    assert_eq!(fs::read(output).unwrap(), bytes);
    a.stop();
    b.stop();
    let served = bootstrap.stop();
    assert_eq!(served.connections, 5);
    assert_eq!(served.rejected_requests, 0);
}

#[test]
fn discovery_and_cell_requests_share_original_connection_and_actual_byte_budgets() {
    let temp = tempfile::tempdir().unwrap();
    let (_origin, manifest, _bytes, path) = fixture(temp.path());
    let provider = Peer::start(&path);
    let bootstrap = Rendezvous::start(&temp.path().join("rendezvous"), &[provider.address]);
    let addresses = policy(&[provider.address, bootstrap.address]);
    let pin = request(manifest.id());
    let value = record(pin, provider.address, 10, 1, wall_now().unwrap().as_secs());
    announce_cell_provider(&value, bootstrap.address, &addresses, limits(), deadline()).unwrap();
    for bytes_only in [false, true] {
        let name = if bytes_only { "byte" } else { "connection" };
        let directory = CellProviderDirectoryV1::open(
            &temp.path().join(format!("directory-{name}")),
            context(),
        )
        .unwrap();
        let store =
            CellStoreV1::open(&temp.path().join(format!("store-{name}")), cache_config()).unwrap();
        let output = temp.path().join(format!("no-output-{name}"));
        let mut bounded = limits();
        if bytes_only {
            bounded.max_response_bytes = (9 + 1 + 335) as u64;
        } else {
            bounded.max_connections = 1;
        }
        let options = CellDiscoveryOptionsV1 {
            request: pin,
            bootstraps: vec![bootstrap.address],
            addresses: addresses.clone(),
        };
        let result = fetch_discovered_cell_to_file(
            &store,
            &directory,
            &options,
            bounded,
            deadline(),
            &output,
        );
        assert!(
            result.is_err(),
            "a fresh fetch budget would incorrectly publish bytes"
        );
        assert_eq!(directory.usage().unwrap().retained_identities, 1);
        assert!(!output.exists());
        assert!(store.manifest(manifest.id()).unwrap().is_none());
        if bytes_only {
            assert!(matches!(
                result,
                Err(CellErrorV1::ResponseByteBudgetExhausted {
                    received_response_bytes: 345,
                    max_response_bytes: 345
                })
            ));
        }
    }
    assert_eq!(
        provider.stop(),
        0,
        "metadata discovery must not reset the original budget"
    );
    assert_eq!(bootstrap.stop().connections, 3);
}

#[test]
fn first_manifest_read_preserves_cold_warm_status_and_exact_rejection_counts() {
    let temp = tempfile::tempdir().unwrap();
    let (origin, manifest, bytes, path) = fixture(temp.path());
    let provider = Peer::start(&path);
    let absent = TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable = absent.local_addr().unwrap();
    let bootstrap = Rendezvous::start(
        &temp.path().join("rendezvous"),
        &[unavailable, provider.address],
    );
    let addresses = policy(&[unavailable, provider.address, bootstrap.address]);
    let pin = request(manifest.id());
    let now = wall_now().unwrap().as_secs();
    // The unavailable endpoint has the first canonical owner key, making the
    // first manifest rejection deterministic rather than dependent on timing.
    let mut owners = [1_u64, 2];
    owners.sort_by_key(|owner| key(*owner).verifying_key().to_bytes());
    for (owner, endpoint) in owners.into_iter().zip([unavailable, provider.address]) {
        announce_cell_provider(
            &record(pin, endpoint, owner, 1, now),
            bootstrap.address,
            &addresses,
            limits(),
            deadline(),
        )
        .unwrap();
    }
    drop(absent);
    let consumer = CellStoreV1::open(&temp.path().join("consumer"), cache_config()).unwrap();
    // Verified chunks exist, but the manifest is genuinely absent. Thus the
    // one rejected Cell response is only the initial manifest attempt.
    for chunk in manifest.chunks() {
        consumer
            .put_chunk(chunk, &origin.chunk(chunk.sha256).unwrap().unwrap())
            .unwrap();
    }
    assert!(consumer.manifest(manifest.id()).unwrap().is_none());
    let directory =
        CellProviderDirectoryV1::open(&temp.path().join("directory"), context()).unwrap();
    let options = CellDiscoveryOptionsV1 {
        request: pin,
        bootstraps: vec![bootstrap.address],
        addresses,
    };
    let (received, cold) = fetch_discovered_cell_to_file(
        &consumer,
        &directory,
        &options,
        limits(),
        deadline(),
        &temp.path().join("cold"),
    )
    .unwrap();
    assert_eq!(received, manifest);
    assert!(!cold.manifest_initial_cache_hit);
    assert_eq!(cold.fetch.rejected_responses, 1);
    assert_eq!(
        cold.fetch.connection_attempts,
        cold.discovery.connection_attempts + 2
    );
    assert_eq!(
        cold.fetch.received_response_bytes,
        cold.discovery.received_response_bytes + 9 + manifest.encode().len() as u64
    );
    assert_eq!(cold.fetch.downloaded_chunks, 0);
    let (_, warm) = fetch_discovered_cell_to_file(
        &consumer,
        &directory,
        &options,
        limits(),
        deadline(),
        &temp.path().join("warm"),
    )
    .unwrap();
    assert!(warm.manifest_initial_cache_hit);
    assert_eq!(warm.fetch.rejected_responses, 0);
    assert_eq!(
        warm.fetch.connection_attempts,
        warm.discovery.connection_attempts
    );
    assert_eq!(
        warm.fetch.received_response_bytes,
        warm.discovery.received_response_bytes
    );
    assert_eq!(warm.fetch.cached_chunks, manifest.chunks().len());
    assert_eq!(warm.fetch.downloaded_chunks, 0);
    assert_eq!(fs::read(temp.path().join("cold")).unwrap(), bytes);
    assert_eq!(fs::read(temp.path().join("warm")).unwrap(), bytes);
    assert_eq!(provider.stop(), 1);
    assert_eq!(bootstrap.stop().connections, 4);
}

#[test]
fn cached_advertisements_cannot_replace_an_actual_bootstrap_reply() {
    let temp = tempfile::tempdir().unwrap();
    let (_origin, manifest, _bytes, path) = fixture(temp.path());
    let provider = Peer::start(&path);
    let failed = TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable = failed.local_addr().unwrap();
    let directory =
        CellProviderDirectoryV1::open(&temp.path().join("directory"), context()).unwrap();
    let now = wall_now().unwrap().as_secs();
    let pin = request(manifest.id());
    accept(
        &directory,
        &record(pin, provider.address, 1, 1, now),
        loopback(),
        now,
    )
    .unwrap();
    drop(failed);
    let store = CellStoreV1::open(&temp.path().join("consumer"), cache_config()).unwrap();
    let output = temp.path().join("no-output");
    let options = CellDiscoveryOptionsV1 {
        request: pin,
        bootstraps: vec![unavailable],
        addresses: policy(&[provider.address, unavailable]),
    };
    assert!(fetch_discovered_cell_to_file(
        &store,
        &directory,
        &options,
        limits(),
        deadline(),
        &output
    )
    .is_err());
    assert!(!output.exists());
    assert_eq!(provider.stop(), 0);
}

#[test]
fn canonical_record_binds_every_field_and_rejects_invalid_signature_time_and_encoding() {
    let endpoint = "127.0.0.1:31234".parse().unwrap();
    let addresses = policy(&[endpoint]);
    let pin = request([11; 32]);
    let now = wall_now().unwrap().as_secs();
    let value = record(pin, endpoint, 11, 1, now);
    let bytes = value.encode();
    assert_eq!(bytes.len(), CELL_PROVIDER_RECORD_BYTES_V1);
    assert_eq!(CellProviderRecordV1::decode(&bytes).unwrap(), value);
    value.verify_at(pin, now, &addresses).unwrap();
    for offset in [
        4, 36, 68, 100, 132, 164, 196, 228, 241, 245, 247, 255, 263, 271, 334,
    ] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(
            CellProviderRecordV1::decode(&changed)
                .and_then(|record| record.verify_at(pin, now, &addresses))
                .is_err(),
            "unsigned mutation at {offset}"
        );
    }
    for end in 0..bytes.len() {
        assert!(CellProviderRecordV1::decode(&bytes[..end]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(CellProviderRecordV1::decode(&extra).is_err());
    assert!(value.verify_at(pin, now + 300, &addresses).is_err());
    assert!(record(pin, endpoint, 11, 2, now + 6)
        .verify_at(pin, now, &addresses)
        .is_err());
    let mut zero = value.clone();
    zero.statement.sequence = 0;
    assert!(zero.shape().is_err());
    let mut ttl = value.clone();
    ttl.statement.expires_unix_seconds += 1;
    assert!(ttl.shape().is_err());
    let mut noncanonical = value.clone();
    noncanonical.statement.owner = [255; 32];
    assert!(noncanonical.verify_signature().is_err());
    let mut weak = value.clone();
    weak.statement.owner = [0; 32];
    weak.statement.owner[0] = 1;
    assert!(weak.verify_signature().is_err());
    let mut r = value.clone();
    r.signature[..32].fill(255);
    assert!(r.verify_signature().is_err());
    let mut negative_zero = value;
    negative_zero.signature[..32].fill(0);
    negative_zero.signature[0] = 1;
    negative_zero.signature[31] = 128;
    assert!(negative_zero.verify_signature().is_err());
}

#[test]
fn explicit_scopes_reject_loopback_linklocal_multicast_mapped_and_unlisted_ports() {
    let scope = CellDiscoveryAddressPolicyV1::ScopedDeployment {
        cidrs: vec![
            CellDiscoveryCidrV1::new("10.40.0.0".parse().unwrap(), 16).unwrap(),
            CellDiscoveryCidrV1::new("fd12:3400::".parse().unwrap(), 32).unwrap(),
        ],
        ports: vec![31234],
    };
    for address in ["10.40.0.1:31234", "[fd12:3400::1]:31234"] {
        scope.check(address.parse().unwrap()).unwrap();
    }
    for address in [
        "10.40.0.1:31235",
        "10.41.0.1:31234",
        "127.0.0.1:31234",
        "169.254.1.1:31234",
        "224.0.0.1:31234",
        "[fe80::1]:31234",
        "[::ffff:10.40.0.1]:31234",
        "0.0.0.0:31234",
    ] {
        assert!(scope.check(address.parse().unwrap()).is_err());
    }
    assert!(CellDiscoveryCidrV1::new("0.0.0.0".parse().unwrap(), 0).is_err());
    assert!(CellDiscoveryCidrV1::new("10.40.0.1".parse().unwrap(), 16).is_err());
    let endpoint = "127.0.0.1:31234".parse().unwrap();
    assert!(CellDiscoveryAddressPolicyV1::LoopbackDevOnly {
        ports: vec![31234; 17]
    }
    .check(endpoint)
    .is_err());
    // An excluded bootstrap fails before any connection or directory mutation.
    let temp = tempfile::tempdir().unwrap();
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let directory =
        CellProviderDirectoryV1::open(&temp.path().join("directory"), context()).unwrap();
    let store = CellStoreV1::open(&temp.path().join("store"), cache_config()).unwrap();
    let options = CellDiscoveryOptionsV1 {
        request: request([10; 32]),
        bootstraps: vec![trap.local_addr().unwrap()],
        addresses: scope,
    };
    assert!(fetch_discovered_cell_to_file(
        &store,
        &directory,
        &options,
        limits(),
        deadline(),
        &temp.path().join("out")
    )
    .is_err());
    assert!(matches!(trap.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
    assert_eq!(directory.usage().unwrap().retained_identities, 0);
}

#[test]
fn expired_records_keep_highwater_across_restart_and_clock_rollback_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let directory = CellProviderDirectoryV1::open(&path, context()).unwrap();
    let now = wall_now().unwrap().as_secs();
    let pin = request([11; 32]);
    let endpoint = "127.0.0.1:31234".parse().unwrap();
    let second = record(pin, endpoint, 1, 2, now);
    accept(&directory, &second, loopback(), now).unwrap();
    drop(directory);
    let directory = CellProviderDirectoryV1::open(&path, context()).unwrap();
    assert!(accept(
        &directory,
        &record(pin, endpoint, 1, 1, now),
        loopback(),
        now
    )
    .is_err());
    assert!(accept(
        &directory,
        &record(pin, endpoint, 1, 2, now + 1),
        loopback(),
        now + 1
    )
    .is_err());
    let after_expiry = now + 301;
    let retained = directory.records(pin, after_expiry, deadline()).unwrap();
    assert_eq!(retained.len(), 1);
    assert!(retained[0].live_at(after_expiry).is_err());
    assert_eq!(directory.usage().unwrap().retained_identities, 1);
    drop(directory);
    let directory = CellProviderDirectoryV1::open(&path, context()).unwrap();
    assert!(directory
        .records(pin, after_expiry - 1, deadline())
        .is_err());
    assert!(accept(
        &directory,
        &record(pin, endpoint, 1, 1, after_expiry),
        loopback(),
        after_expiry
    )
    .is_err());
    accept(
        &directory,
        &record(pin, endpoint, 1, 3, after_expiry),
        loopback(),
        after_expiry,
    )
    .unwrap();
    assert_eq!(
        directory.records(pin, after_expiry, deadline()).unwrap()[0]
            .statement
            .sequence,
        3
    );
}

#[test]
fn lookup_rejects_old_signed_wire_with_retained_new_highwater_columns() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let directory = CellProviderDirectoryV1::open(&path, context()).unwrap();
    let now = wall_now().unwrap().as_secs();
    let pin = request([11; 32]);
    let endpoint = "127.0.0.1:31234".parse().unwrap();
    let old = record(pin, endpoint, 1, 1, now);
    let current = record(pin, endpoint, 1, 2, now);
    accept(&directory, &old, loopback(), now).unwrap();
    accept(&directory, &current, loopback(), now).unwrap();
    let external = Connection::open(&path).unwrap();
    external
        .execute("UPDATE discovery_providers_v1 SET wire=?1", [old.encode()])
        .unwrap();
    assert!(
        directory.records(pin, now, deadline()).is_err(),
        "lookup must not emit a valid old wire over inconsistent new sequence/digest columns"
    );
    assert!(accept(&directory, &current, loopback(), now).is_err());
    external
        .execute(
            "UPDATE discovery_providers_v1 SET wire=?1",
            [current.encode()],
        )
        .unwrap();
    assert_eq!(
        directory.records(pin, now, deadline()).unwrap(),
        vec![current]
    );
    external
        .execute(
            "UPDATE discovery_providers_v1 SET prefix=?1",
            [[7_u8; 17].as_slice()],
        )
        .unwrap();
    assert!(
        directory.records(pin, now, deadline()).is_err(),
        "a corrupted source quota prefix cannot become a lookup result"
    );
}

#[test]
fn live_schema_namespace_and_same_path_replacement_cannot_manufacture_publication_ack() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let directory = CellProviderDirectoryV1::open(&path, context()).unwrap();
    let now = wall_now().unwrap().as_secs();
    let pin = request([11; 32]);
    let endpoint = "127.0.0.1:31234".parse().unwrap();
    let value = record(pin, endpoint, 1, 1, now);
    let external = Connection::open(&path).unwrap();
    external.execute_batch("CREATE TRIGGER suppress_discovery BEFORE INSERT ON discovery_providers_v1 BEGIN SELECT RAISE(IGNORE); END").unwrap();
    assert!(accept(&directory, &value, loopback(), now).is_err());
    assert_eq!(
        external
            .query_row::<u64, _, _>("SELECT count(*) FROM discovery_providers_v1", [], |r| r
                .get(0))
            .unwrap(),
        0
    );
    external
        .execute_batch("DROP TRIGGER suppress_discovery")
        .unwrap();
    accept(&directory, &value, loopback(), now).unwrap();
    let mut wrong = context();
    wrong.namespace = [88; 32];
    external
        .execute("UPDATE discovery_meta_v1 SET context=?1", [wrong.encode()])
        .unwrap();
    assert!(accept(&directory, &value, loopback(), now).is_err());
    assert!(directory.records(pin, now, deadline()).is_err());
    external
        .execute(
            "UPDATE discovery_meta_v1 SET context=?1",
            [context().encode()],
        )
        .unwrap();
    drop(external);
    fs::rename(&path, temp.path().join("retained-original")).unwrap();
    let replacement = CellProviderDirectoryV1::open(&path, context()).unwrap();
    drop(replacement);
    assert!(accept(&directory, &value, loopback(), now).is_err());
    assert!(directory.records(pin, now, deadline()).is_err());
    assert!(directory.usage().is_err());
    // Stable replacement is detected; this test makes no claim about a fully
    // malicious host racing A -> B -> A around filesystem observations.
}

#[test]
fn tcp_publication_ack_requires_live_schema_and_actual_persisted_highwater() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let endpoint = "127.0.0.1:31234".parse().unwrap();
    let bootstrap = Rendezvous::start(&path, &[endpoint]);
    let addresses = policy(&[endpoint, bootstrap.address]);
    let now = wall_now().unwrap().as_secs();
    let value = record(request([11; 32]), endpoint, 1, 1, now);
    let external = Connection::open(&path).unwrap();
    external.execute_batch("CREATE TRIGGER suppress_discovery BEFORE INSERT ON discovery_providers_v1 BEGIN SELECT RAISE(IGNORE); END").unwrap();
    assert!(
        announce_cell_provider(&value, bootstrap.address, &addresses, limits(), deadline())
            .is_err()
    );
    assert_eq!(
        external
            .query_row::<u64, _, _>("SELECT count(*) FROM discovery_providers_v1", [], |r| r
                .get(0))
            .unwrap(),
        0
    );
    external
        .execute_batch("DROP TRIGGER suppress_discovery")
        .unwrap();
    announce_cell_provider(&value, bootstrap.address, &addresses, limits(), deadline()).unwrap();
    let actual: Vec<u8> = external
        .query_row("SELECT wire FROM discovery_providers_v1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(actual, value.encode());
    let changed = record(request([11; 32]), endpoint, 1, 2, now);
    external.execute_batch("CREATE TRIGGER suppress_update BEFORE UPDATE ON discovery_providers_v1 BEGIN SELECT RAISE(IGNORE); END").unwrap();
    assert!(announce_cell_provider(
        &changed,
        bootstrap.address,
        &addresses,
        limits(),
        deadline()
    )
    .is_err());
    let actual: Vec<u8> = external
        .query_row("SELECT wire FROM discovery_providers_v1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(actual, value.encode());
    let served = bootstrap.stop();
    assert_eq!(served.connections, 3);
    assert_eq!(served.rejected_requests, 2);
}

#[test]
fn fixed_512_identity_capacity_survives_expiry_and_never_evicts_for_new_keys() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("directory");
    let directory = CellProviderDirectoryV1::open(&path, context()).unwrap();
    let now = wall_now().unwrap().as_secs();
    let endpoint = "127.0.0.1:31234".parse().unwrap();
    for index in 0_u64..512 {
        let manifest: [u8; 32] = Sha256::digest(index.to_be_bytes()).into();
        // Four fixed /24 groups, each 128 identities; four source IPs in each,
        // 32 identities per source. Owner/manifest keys are all distinct.
        let source = IpAddr::V4(Ipv4Addr::new(
            10,
            (index / 128) as u8,
            0,
            1 + ((index % 128) / 32) as u8,
        ));
        accept(
            &directory,
            &record(request(manifest), endpoint, index + 1, 1, now),
            source,
            now,
        )
        .unwrap();
    }
    let usage = directory.usage().unwrap();
    assert_eq!(usage.retained_identities, 512);
    assert_eq!(usage.retained_wire_bytes, 512 * 335);
    assert!(usage.database_bytes <= usage.maximum_database_bytes);
    assert!(!usage.database_bound_includes_journal_or_rss);
    let extra = record(request([99; 32]), endpoint, 900, 1, now + 301);
    assert!(matches!(
        accept(&directory, &extra, "10.9.0.1".parse().unwrap(), now + 301),
        Err(CellErrorV1::Invalid("discovery identity capacity"))
    ));
    let first: [u8; 32] = Sha256::digest(0_u64.to_be_bytes()).into();
    accept(
        &directory,
        &record(request(first), endpoint, 1, 2, now + 301),
        loopback(),
        now + 301,
    )
    .unwrap();
    assert_eq!(directory.usage().unwrap().retained_identities, 512);
    drop(directory);
    let reopened = CellProviderDirectoryV1::open(&path, context()).unwrap();
    assert_eq!(reopened.usage().unwrap().retained_identities, 512);
    assert!(accept(&reopened, &extra, "10.9.0.1".parse().unwrap(), now + 301).is_err());
}

#[test]
fn owner_manifest_and_observed_source_limits_are_independent_permanent_caps() {
    let temp = tempfile::tempdir().unwrap();
    let endpoint = "127.0.0.1:31234".parse().unwrap();
    for (kind, cap) in [
        ("owner", 16_u64),
        ("manifest", 16),
        ("source", 64),
        ("prefix", 128),
    ] {
        let directory = CellProviderDirectoryV1::open(&temp.path().join(kind), context()).unwrap();
        let now = wall_now().unwrap().as_secs();
        for index in 0..=cap {
            let owner = if kind == "owner" { 1 } else { index + 1 };
            let manifest = if kind == "manifest" {
                [11; 32]
            } else {
                Sha256::digest(index.to_be_bytes()).into()
            };
            let source = if kind == "prefix" {
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1 + (index / 32) as u8))
            } else {
                loopback()
            };
            let result = accept(
                &directory,
                &record(request(manifest), endpoint, owner, 1, now),
                source,
                now,
            );
            if index < cap {
                result.unwrap();
            } else {
                assert!(
                    matches!(
                        result,
                        Err(CellErrorV1::Invalid("discovery identity capacity"))
                    ),
                    "{kind}"
                );
            }
        }
        assert_eq!(directory.usage().unwrap().retained_identities, cap);
    }
}

#[test]
fn oversized_and_partial_tcp_replies_debit_actual_bytes_and_do_not_reopen_attempts() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for index in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = [0; 199];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], b"CDQ1");
            let mut header = b"CDS1\0".to_vec();
            header.extend(u32::MAX.to_be_bytes());
            if index == 0 {
                stream.write_all(&header).unwrap();
            } else {
                let _ = stream.write_all(&header[..3]);
            }
        }
    });
    let requests = AtomicU64::new(2);
    let responses = ResponseBudget::new(12);
    let transport = RequestContext {
        timeout: Duration::from_millis(200),
        overall: deadline(),
        requests_left: &requests,
        responses: &responses,
    };
    let mut observed = CellDiscoveryObservationV1::default();
    let body = request([11; 32]).encode();
    assert!(transport::exchange(address, 1, &body, 2681, &transport, &mut observed).is_err());
    assert_eq!(observed.received_response_bytes, 9);
    assert!(transport::exchange(address, 1, &body, 2681, &transport, &mut observed).is_err());
    assert_eq!(observed.received_response_bytes, 12);
    assert_eq!(responses.received().unwrap(), 12);
    assert!(transport::exchange(address, 1, &body, 2681, &transport, &mut observed).is_err());
    assert_eq!(observed.connection_attempts, 2);
    assert_eq!(requests.load(Ordering::Relaxed), 0);
    server.join().unwrap();
}

#[test]
fn slowloris_retains_one_absolute_deadline_and_counts_partial_response_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut request = [0; 199];
        stream.read_exact(&mut request).unwrap();
        for byte in b"CDS1\0\0\0\0\x01" {
            if stream.write_all(&[*byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    let requests = AtomicU64::new(4);
    let responses = ResponseBudget::new(1000);
    let started = Instant::now();
    let original = started + Duration::from_millis(65);
    let transport = RequestContext {
        timeout: Duration::from_secs(2),
        overall: original,
        requests_left: &requests,
        responses: &responses,
    };
    let mut observed = CellDiscoveryObservationV1::default();
    let body = request([11; 32]).encode();
    assert!(transport::exchange(address, 1, &body, 2681, &transport, &mut observed).is_err());
    assert!(observed.received_response_bytes > 0 && observed.received_response_bytes < 9);
    assert_eq!(
        observed.received_response_bytes,
        responses.received().unwrap()
    );
    assert!(transport::exchange(address, 1, &body, 2681, &transport, &mut observed).is_err());
    assert_eq!(
        observed.connection_attempts, 1,
        "an expired parent cannot acquire a new attempt"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    server.join().unwrap();
}

#[test]
fn bad_advertisement_cannot_trigger_an_unscoped_dial_or_grant_a_candidate() {
    let temp = tempfile::tempdir().unwrap();
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bootstrap = listener.local_addr().unwrap();
    let pin = request([11; 32]);
    let value = record(
        pin,
        trap.local_addr().unwrap(),
        1,
        1,
        wall_now().unwrap().as_secs(),
    );
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = [0; 199];
            stream.read_exact(&mut request).unwrap();
            let mut body = vec![1];
            body.extend(value.encode());
            let mut reply = b"CDS1\0".to_vec();
            reply.extend((body.len() as u32).to_be_bytes());
            reply.extend(body);
            stream.write_all(&reply).unwrap();
        }
    });
    let directory =
        CellProviderDirectoryV1::open(&temp.path().join("directory"), context()).unwrap();
    let requests = AtomicU64::new(8);
    let responses = ResponseBudget::new(4096);
    let transport = RequestContext {
        timeout: Duration::from_millis(200),
        overall: deadline(),
        requests_left: &requests,
        responses: &responses,
    };
    let options = CellDiscoveryOptionsV1 {
        request: pin,
        bootstraps: vec![bootstrap],
        addresses: policy(&[bootstrap]),
    };
    let mut observed = CellDiscoveryObservationV1::default();
    assert!(transport::discover(&directory, &options, &transport, &mut observed).is_err());
    assert_eq!(observed.record_validation_attempts, 2);
    assert_eq!(observed.rejected_records, 2);
    assert_eq!(observed.received_response_bytes, 690);
    assert_eq!(directory.usage().unwrap().retained_identities, 0);
    assert!(matches!(trap.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
    server.join().unwrap();
}

#[test]
fn four_bootstraps_exhaust_exact_eight_attempts_and_64_validation_slots_without_referrals() {
    let temp = tempfile::tempdir().unwrap();
    let pin = request([11; 32]);
    let endpoint = "127.0.0.1:31234".parse().unwrap();
    let mut invalid = record(pin, endpoint, 1, 1, wall_now().unwrap().as_secs());
    invalid.signature[63] ^= 1;
    let mut peers = Vec::new();
    let mut workers = Vec::new();
    for _ in 0..4 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        peers.push(listener.local_addr().unwrap());
        let value = invalid.clone();
        workers.push(thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut request = [0; 199];
                stream.read_exact(&mut request).unwrap();
                let mut body = vec![8];
                for _ in 0..8 {
                    body.extend(value.encode());
                }
                let mut reply = b"CDS1\0".to_vec();
                reply.extend((body.len() as u32).to_be_bytes());
                reply.extend(body);
                stream.write_all(&reply).unwrap();
            }
        }));
    }
    let mut permitted = peers.clone();
    permitted.push(endpoint);
    let options = CellDiscoveryOptionsV1 {
        request: pin,
        bootstraps: peers,
        addresses: policy(&permitted),
    };
    let directory =
        CellProviderDirectoryV1::open(&temp.path().join("directory"), context()).unwrap();
    let requests = AtomicU64::new(100);
    let responses = ResponseBudget::new(100_000);
    let transport = RequestContext {
        timeout: Duration::from_millis(200),
        overall: deadline(),
        requests_left: &requests,
        responses: &responses,
    };
    let mut observed = CellDiscoveryObservationV1::default();
    assert!(transport::discover(&directory, &options, &transport, &mut observed).is_err());
    assert_eq!(observed.connection_attempts, 8);
    assert_eq!(requests.load(Ordering::Relaxed), 92);
    assert_eq!(observed.record_validation_attempts, 64);
    assert_eq!(observed.rejected_records, 64);
    assert_eq!(observed.received_response_bytes, 8 * (9 + 1 + 8 * 335));
    assert_eq!(
        responses.received().unwrap(),
        observed.received_response_bytes
    );
    assert_eq!(directory.usage().unwrap().retained_identities, 0);
    for worker in workers {
        worker.join().unwrap();
    }
}

// Explicit finite fixture quota; covers the existing <=32MiB commit fixtures.
fn cache_config() -> crate::cell::CellCacheConfigV2 {
    crate::cell::CellCacheConfigV2 {
        max_logical_bytes: 64 * 1024 * 1024,
        max_chunk_rows: 4096,
        max_manifest_rows: 256,
    }
}
