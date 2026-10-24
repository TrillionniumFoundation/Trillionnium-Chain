//! Real TCP regressions for one advertising owner's sequence high-water mark.
//! These are transport fixtures, not independent custody or model qualification.

use std::{
    fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
};

use super::super::{serve_cells, CellManifestV1, CellPeerLimitsV1, CellStoreV1};
use super::*;

fn context() -> CellDiscoveryContextV1 {
    CellDiscoveryContextV1 {
        namespace: [31; 32],
        network: [32; 32],
        parameters: [33; 32],
        genesis: [34; 32],
    }
}

fn cell_context() -> CellContextV1 {
    CellContextV1 {
        family: "discovery-sequence-native-test-v1".into(),
        base: [35; 32],
        parent: [36; 32],
        tokenizer: [37; 32],
        layout: [38; 32],
        runtime: [39; 32],
    }
}

fn request(manifest: CellDigestV1) -> CellDiscoveryRequestV1 {
    CellDiscoveryRequestV1 {
        context: context(),
        cell_context: cell_discovery_context_digest(&cell_context()).unwrap(),
        manifest,
    }
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

fn deadline() -> Instant {
    Instant::now() + limits().overall_timeout
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
    sequence: u64,
    issued: u64,
    ttl: u64,
) -> CellProviderRecordV1 {
    // Both rendezvous receive signatures from this one exact advertising key.
    let key = SigningKey::from_bytes(&Sha256::digest(b"pn5-sequence-tcp-test-owner").into());
    CellProviderRecordV1::sign(
        CellProviderStatementV1 {
            request: pin,
            owner: key.verifying_key().to_bytes(),
            endpoint,
            sequence,
            issued_unix_seconds: issued,
            expires_unix_seconds: issued + ttl,
        },
        &key,
    )
    .unwrap()
}

fn fixture(path: &Path) -> (CellManifestV1, Vec<u8>, PathBuf) {
    let bytes: Vec<_> = (0_u32..257)
        .flat_map(|n| <[u8; 32]>::from(Sha256::digest(n.to_be_bytes())))
        .collect();
    let input = path.join("actual-cell-input");
    fs::write(&input, &bytes).unwrap();
    let store_path = path.join("origin.sqlite");
    let store = CellStoreV1::open(&store_path, cache_config()).unwrap();
    let manifest = store.pack_file(&input, cell_context(), 16_384).unwrap();
    (manifest, bytes, store_path)
}

struct Peer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<CellResultV1<u64>>>,
}

impl Peer {
    fn start(path: &Path, bounds: CellPeerLimitsV1) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let path = path.to_owned();
        let handle = thread::spawn(move || {
            let store = CellStoreV1::open(&path, cache_config())?;
            serve_cells(&listener, &store, &stop, bounds)
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
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<CellResultV1<CellRendezvousReportV1>>>,
}

impl Rendezvous {
    fn start(path: &Path, providers: &[SocketAddr]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let addresses = policy(providers);
        let directory = CellProviderDirectoryV1::open(path, context()).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let handle = thread::spawn(move || {
            serve_cell_rendezvous(
                &listener,
                &directory,
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

/// Accept real connections and keep them open without sending any reply.
/// This detects an actual stale dial, including a dial whose fetch later falls
/// back to a current provider and ultimately returns the correct payload.
struct SilentTrap {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    accepted: Arc<AtomicU64>,
    handle: Option<JoinHandle<io::Result<()>>>,
}

impl SilentTrap {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let accepted = Arc::new(AtomicU64::new(0));
        let observed = accepted.clone();
        let handle = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(30);
            let mut held = Vec::new();
            while !stop.load(Ordering::Relaxed) && held.len() < 64 && Instant::now() < end {
                match listener.accept() {
                    Ok((stream, _)) => {
                        held.push(stream);
                        observed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Self {
            address,
            shutdown,
            accepted,
            handle: Some(handle),
        }
    }

    fn stop(mut self) -> u64 {
        self.shutdown.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap().unwrap();
        self.accepted.load(Ordering::Relaxed)
    }
}

impl Drop for SilentTrap {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Debug)]
struct ExpiryObservation {
    request_arrived: Duration,
    actual_backend_frame_ready: Duration,
    reply_attempted: Duration,
}

/// Forward actual request/response bytes to the existing Cell TCP server. Only
/// the first manifest reply is withheld until after the signed expiry; no
/// manifest, chunk, signature, hash, or successful reply is fabricated here.
struct ExpiryProxy {
    address: SocketAddr,
    expiry: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    observation: Arc<Mutex<Option<ExpiryObservation>>>,
    handle: Option<JoinHandle<io::Result<()>>>,
}

impl ExpiryProxy {
    fn start(backend: SocketAddr, bounds: CellPeerLimitsV1) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let expiry = Arc::new(AtomicU64::new(0));
        let published_expiry = expiry.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let observation = Arc::new(Mutex::new(None));
        let observed = observation.clone();
        let handle = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(30);
            let mut connections = 0;
            let mut delayed = false;
            while !stop.load(Ordering::Relaxed) && connections < 64 && Instant::now() < end {
                let mut client = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                };
                connections += 1;
                client.set_read_timeout(Some(bounds.request_timeout))?;
                client.set_write_timeout(Some(bounds.request_timeout))?;
                let mut query = [0_u8; 37];
                client.read_exact(&mut query)?;
                if &query[..4] != b"TCQ1" || !matches!(query[4], 1 | 2) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "actual Cell request",
                    ));
                }
                let arrived = wall_now().unwrap();
                let mut upstream = TcpStream::connect_timeout(&backend, bounds.request_timeout)?;
                upstream.set_read_timeout(Some(bounds.request_timeout))?;
                upstream.set_write_timeout(Some(bounds.request_timeout))?;
                upstream.write_all(&query)?;
                let mut header = [0_u8; 9];
                upstream.read_exact(&mut header)?;
                let length = u32::from_be_bytes(header[5..].try_into().unwrap()) as usize;
                if &header[..4] != b"TCS1" || header[4] != 0 || !(1..=1_048_576).contains(&length) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "actual Cell response",
                    ));
                }
                let mut body = vec![0_u8; length];
                upstream.read_exact(&mut body)?;
                if !delayed {
                    if query[4] != 1 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "first response must be manifest",
                        ));
                    }
                    let ready = wall_now().unwrap();
                    let expires = published_expiry.load(Ordering::Acquire);
                    if expires == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "signed expiry not armed",
                        ));
                    }
                    let release_at = Duration::from_secs(expires) + Duration::from_millis(25);
                    if let Some(wait) = release_at.checked_sub(ready) {
                        // The caller publishes a two-second TTL. This bound is
                        // fixture cleanup, not extra time granted to the fetch.
                        if wait > Duration::from_secs(3) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "unexpected expiry delay",
                            ));
                        }
                        thread::sleep(wait);
                    }
                    *observed.lock().unwrap() = Some(ExpiryObservation {
                        request_arrived: arrived,
                        actual_backend_frame_ready: ready,
                        reply_attempted: wall_now().unwrap(),
                    });
                    delayed = true;
                }
                // A correct client may have closed at signed expiry. Its
                // resulting closed socket is expected; upstream I/O above
                // must still have succeeded to count this fixture as valid.
                match client
                    .write_all(&header)
                    .and_then(|()| client.write_all(&body))
                {
                    Ok(()) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::BrokenPipe
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                        ) => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Self {
            address,
            expiry,
            shutdown,
            observation,
            handle: Some(handle),
        }
    }

    fn arm(&self, signed_expiry: u64) {
        self.expiry.store(signed_expiry, Ordering::Release);
    }

    fn stop(mut self) -> ExpiryObservation {
        self.shutdown.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap().unwrap();
        let observed = self
            .observation
            .lock()
            .unwrap()
            .take()
            .expect("a real manifest request must reach the proxy while live");
        observed
    }
}

impl Drop for ExpiryProxy {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn assert_current_sequence(
    directory: &CellProviderDirectoryV1,
    pin: CellDiscoveryRequestV1,
    sequence: u64,
) {
    let rows = directory
        .records(pin, wall_now().unwrap().as_secs(), deadline())
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].statement().sequence, sequence);
}

#[test]
fn tcp_two_bootstraps_newer_owner_sequence_never_dials_superseded_endpoint() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest, bytes, source) = fixture(temp.path());
    let current = Peer::start(&source, limits());
    let current_address = current.address;
    let stale = SilentTrap::start();
    let endpoints = [stale.address, current.address];
    let first = Rendezvous::start(&temp.path().join("first-directory.sqlite"), &endpoints);
    let second = Rendezvous::start(&temp.path().join("second-directory.sqlite"), &endpoints);
    let addresses = policy(&[
        stale.address,
        current.address,
        first.address,
        second.address,
    ]);
    let pin = request(manifest.id());
    let now = wall_now().unwrap().as_secs();
    let old = record(pin, stale.address, 1, now, 300);
    let latest = record(pin, current.address, 2, now, 300);
    for (value, rendezvous) in [(&old, first.address), (&latest, second.address)] {
        let receipt =
            announce_cell_provider(value, rendezvous, &addresses, limits(), deadline()).unwrap();
        assert_eq!(receipt.connection_attempts, 1);
        assert_eq!(receipt.received_response_bytes, 41);
    }
    let consumer = CellStoreV1::open(&temp.path().join("consumer.sqlite"), cache_config()).unwrap();
    let directory =
        CellProviderDirectoryV1::open(&temp.path().join("consumer-directory.sqlite"), context())
            .unwrap();
    let output = temp.path().join("downloaded-cell");
    // No provider addresses are preconfigured in the fetch: each signed record
    // is obtained from its separately populated, actual TCP rendezvous.
    let options = CellDiscoveryOptionsV1 {
        request: pin,
        bootstraps: vec![first.address, second.address],
        addresses,
    };
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
    assert_current_sequence(&directory, pin, 2);
    let stale_dials = stale.stop();
    assert!(
        current.stop() >= 2,
        "the original Cell server supplied manifest and payload"
    );
    for served in [first.stop(), second.stop()] {
        assert_eq!(served.connections, 2);
        assert_eq!(served.rejected_requests, 0);
    }
    assert_eq!(
        stale_dials, 0,
        "the superseded endpoint must receive no actual TCP connection"
    );
    assert_eq!(report.discovery.record_validation_attempts, 2);
    assert_eq!(report.discovered_providers, vec![current_address]);
    assert_eq!(
        report.fetch.supplying_peers.into_iter().collect::<Vec<_>>(),
        vec![current_address]
    );
}

#[test]
fn tcp_newer_same_endpoint_short_ttl_expires_mid_manifest_without_publication() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest, bytes, source) = fixture(temp.path());
    // This regression declares its fixed four-second per-request allowance at
    // the start, so a real two-second signed TTL can expire during the reply.
    // Nothing is renewed at runtime. The original ten-second overall limit,
    // 64 connections, 4 MiB response budget, and two workers remain unchanged.
    let bounds = CellPeerLimitsV1 {
        request_timeout: Duration::from_secs(4),
        ..limits()
    };
    let backend = Peer::start(&source, bounds);
    let proxy = ExpiryProxy::start(backend.address, bounds);
    let first = Rendezvous::start(
        &temp.path().join("first-directory.sqlite"),
        &[proxy.address],
    );
    let second = Rendezvous::start(
        &temp.path().join("second-directory.sqlite"),
        &[proxy.address],
    );
    let addresses = policy(&[proxy.address, first.address, second.address]);
    let consumer = CellStoreV1::open(&temp.path().join("consumer.sqlite"), cache_config()).unwrap();
    let directory =
        CellProviderDirectoryV1::open(&temp.path().join("consumer-directory.sqlite"), context())
            .unwrap();
    let output = temp.path().join("must-not-publish");
    let pin = request(manifest.id());
    // Prepare all databases/listeners before starting the short signed TTL.
    // Failure to reach the proxy while live is a failed fixture, never a pass.
    let now = wall_now().unwrap().as_secs();
    let old = record(pin, proxy.address, 1, now, 300);
    let latest = record(pin, proxy.address, 2, now, 2);
    let expires = Duration::from_secs(latest.statement().expires_unix_seconds);
    proxy.arm(latest.statement().expires_unix_seconds);
    for (value, rendezvous) in [(&old, first.address), (&latest, second.address)] {
        let receipt =
            announce_cell_provider(value, rendezvous, &addresses, bounds, deadline()).unwrap();
        assert_eq!(receipt.connection_attempts, 1);
        assert_eq!(receipt.received_response_bytes, 41);
    }
    let options = CellDiscoveryOptionsV1 {
        request: pin,
        bootstraps: vec![first.address, second.address],
        addresses,
    };
    let original_deadline = deadline();
    let result = fetch_discovered_cell_to_file(
        &consumer,
        &directory,
        &options,
        bounds,
        original_deadline,
        &output,
    );
    let completed_at = Instant::now();
    let observed = proxy.stop();
    assert!(
        backend.stop() >= 1,
        "the original Cell server returned the actual manifest"
    );
    for served in [first.stop(), second.stop()] {
        assert_eq!(served.connections, 2);
        assert_eq!(served.rejected_requests, 0);
    }
    assert_current_sequence(&directory, pin, 2);
    assert!(
        observed.request_arrived < expires,
        "must start a real transfer while seq2 remains live: {observed:?}"
    );
    assert!(observed.actual_backend_frame_ready < expires, "expiry must occur in the intentional wire delay, not while generating the fixture: {observed:?}");
    assert!(
        observed.reply_attempted > expires,
        "actual TCP reply crosses signed expiry: {observed:?}"
    );
    assert!(
        completed_at < original_deadline,
        "the original overall budget must remain unused; signed TTL is the rejected boundary"
    );
    if result.is_ok() {
        assert_eq!(
            fs::read(&output).unwrap(),
            bytes,
            "the red implementation published actual verified source bytes"
        );
    }
    assert!(
        result.is_err(),
        "latest seq2 TTL must replace the earlier seq1 deadline: {result:?}"
    );
    assert!(
        !output.exists(),
        "expired discovery cannot publish an otherwise valid Cell"
    );
}

#[test]
fn tcp_equal_sequence_endpoint_equivocation_disqualifies_the_identity_without_any_dial() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest, _bytes, source) = fixture(temp.path());
    let first_endpoint = SilentTrap::start();
    let second_endpoint = Peer::start(&source, limits());
    let endpoints = [first_endpoint.address, second_endpoint.address];
    let first = Rendezvous::start(&temp.path().join("first-directory"), &endpoints);
    let second = Rendezvous::start(&temp.path().join("second-directory"), &endpoints);
    let addresses = policy(&[endpoints[0], endpoints[1], first.address, second.address]);
    let pin = request(manifest.id());
    let now = wall_now().unwrap().as_secs();
    let original = record(pin, endpoints[0], 1, now, 300);
    let conflicting = record(pin, endpoints[1], 1, now, 300);
    for (value, bootstrap) in [(&original, first.address), (&conflicting, second.address)] {
        announce_cell_provider(value, bootstrap, &addresses, limits(), deadline()).unwrap();
    }
    let consumer = CellStoreV1::open(&temp.path().join("consumer"), cache_config()).unwrap();
    let directory =
        CellProviderDirectoryV1::open(&temp.path().join("consumer-directory"), context()).unwrap();
    let options = CellDiscoveryOptionsV1 {
        request: pin,
        bootstraps: vec![first.address, second.address],
        addresses,
    };
    let output = temp.path().join("must-not-publish");
    let result = fetch_discovered_cell_to_file(
        &consumer,
        &directory,
        &options,
        limits(),
        deadline(),
        &output,
    );
    let rows = directory
        .records(pin, wall_now().unwrap().as_secs(), deadline())
        .unwrap();
    assert_eq!(
        rows,
        vec![original],
        "a signed equal-sequence conflict cannot replace durable high water"
    );
    let first_dials = first_endpoint.stop();
    let second_dials = second_endpoint.stop();
    for served in [first.stop(), second.stop()] {
        assert!((2..=3).contains(&served.connections));
        assert_eq!(served.rejected_requests, 0);
    }
    assert!(result.is_err());
    assert!(!output.exists());
    assert_eq!(second_dials, 0);
    assert_eq!(
        first_dials, 0,
        "an equivocated owner must not retain its first endpoint as a candidate"
    );
}

// Explicit finite fixture quota; covers the existing <=32MiB commit fixtures.
fn cache_config() -> crate::cell::CellCacheConfigV4 {
    crate::cell::CellCacheConfigV4 {
        max_database_bytes: 128 * 1024 * 1024,
        max_logical_bytes: 64 * 1024 * 1024,
        max_chunk_rows: 4096,
        max_manifest_rows: 256,
    }
}
