//! Real TCP regression for same-sequence equivocation hidden by a newer record.
//! This module is independent of the three already frozen sequence regressions.

use std::{
    fs, io,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
};

use super::super::{CellManifestV1, CellPeerLimitsV1, CellStoreV1};
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
    // All rendezvous receive signatures from this one exact advertising key.
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

#[test]
fn tcp_higher_sequence_cannot_hide_observed_earlier_sequence_equivocation() {
    let temp = tempfile::tempdir().unwrap();
    let (manifest, _bytes, _source) = fixture(temp.path());
    let a = SilentTrap::start();
    let c = SilentTrap::start();
    let b = SilentTrap::start();
    let endpoints = [a.address, c.address, b.address];
    let first = Rendezvous::start(&temp.path().join("a-rendezvous.sqlite"), &endpoints);
    let second = Rendezvous::start(&temp.path().join("c-rendezvous.sqlite"), &endpoints);
    let third = Rendezvous::start(&temp.path().join("b-rendezvous.sqlite"), &endpoints);
    let addresses = policy(&[
        a.address,
        c.address,
        b.address,
        first.address,
        second.address,
        third.address,
    ]);
    let consumer = CellStoreV1::open(&temp.path().join("consumer.sqlite"), cache_config()).unwrap();
    let directory =
        CellProviderDirectoryV1::open(&temp.path().join("consumer-directory.sqlite"), context())
            .unwrap();
    let pin = request(manifest.id());
    let now = wall_now().unwrap().as_secs();
    // All three signatures and pinned contexts are valid. A and B have the
    // same owner/sequence and different endpoints; the intervening C advances
    // that owner's durable high water before B reaches the consumer.
    let first_record = record(pin, a.address, 1, now, 300);
    let higher_record = record(pin, c.address, 2, now, 300);
    let conflict_record = record(pin, b.address, 1, now, 300);
    assert_eq!(
        first_record.statement().owner,
        higher_record.statement().owner
    );
    assert_eq!(
        first_record.statement().owner,
        conflict_record.statement().owner
    );
    assert_eq!(
        first_record.statement().sequence,
        conflict_record.statement().sequence
    );
    assert_ne!(first_record.encode(), conflict_record.encode());
    for (value, rendezvous) in [
        (&first_record, first.address),
        (&higher_record, second.address),
        (&conflict_record, third.address),
    ] {
        let receipt =
            announce_cell_provider(value, rendezvous, &addresses, limits(), deadline()).unwrap();
        assert_eq!(receipt.connection_attempts, 1);
        assert_eq!(receipt.received_response_bytes, 41);
    }
    let options = CellDiscoveryOptionsV1 {
        request: pin,
        // The actual wire lookup order is A(seq1), C(seq2), B(seq1).
        // None of the provider endpoints is supplied as a fetch peer list.
        bootstraps: vec![first.address, second.address, third.address],
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
    assert!(result.is_err());
    assert!(!output.exists());
    // A generic failed fetch is insufficient: the old implementation fails
    // only after actually dialing C. The fixed implementation rejects the
    // equivocated owner during discovery, before dialing any of its endpoints.
    let dials = [a.stop(), c.stop(), b.stop()];
    for served in [first.stop(), second.stop(), third.stop()] {
        // One announce and one or two bounded lookup rounds, unchanged limits.
        assert!((2..=3).contains(&served.connections));
        assert_eq!(served.rejected_requests, 0);
    }
    let rows = directory
        .records(pin, wall_now().unwrap().as_secs(), deadline())
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0], higher_record,
        "durable high water remains seq2 despite exclusion from this operation"
    );
    assert_eq!(dials, [0, 0, 0], "A(seq1), C(seq2), B(seq1) equivocation must exclude this owner before any actual provider TCP dial");
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
