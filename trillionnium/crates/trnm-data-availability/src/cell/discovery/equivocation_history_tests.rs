//! Real TCP regression for same-sequence equivocation hidden by a newer record.
//! This module is independent of the three already frozen sequence regressions.

use std::{
    fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver},
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

fn wait_ready(ready: Receiver<()>, setup_deadline: Instant) {
    let result = ready.recv_timeout(setup_deadline.saturating_duration_since(Instant::now()));
    assert!(
        result.is_ok(),
        "bounded fixture accept-loop readiness: {result:?}"
    );
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
    fn start(path: &Path, providers: &[SocketAddr], setup_deadline: Instant) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let addresses = policy(providers);
        let directory = CellProviderDirectoryV1::open(path, context()).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let (ready, accepting) = mpsc::sync_channel(1);
        let handle = thread::spawn(move || {
            super::transport::serve_cell_rendezvous_with_ready(
                &listener,
                &directory,
                &addresses,
                &stop,
                CellRendezvousLimitsV1 {
                    request_timeout: Duration::from_millis(250),
                    lifetime: Duration::from_secs(30),
                    max_connections: 64,
                },
                ready,
            )
        });
        let server = Self {
            address,
            shutdown,
            handle: Some(handle),
        };
        wait_ready(accepting, setup_deadline);
        server
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
    fn start(setup_deadline: Instant) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let accepted = Arc::new(AtomicU64::new(0));
        let observed = accepted.clone();
        let (ready, accepting) = mpsc::sync_channel(1);
        let handle = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(30);
            let mut held = Vec::new();
            let mut ready = Some(ready);
            while held.len() < 64 && Instant::now() < end {
                let accepted = listener.accept();
                if let Some(ready) = ready.take() {
                    let _ = ready.send(());
                }
                match accepted {
                    Ok((stream, _)) => {
                        held.push(stream);
                        observed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        // Drain already-established connections before shutdown;
                        // scheduling cannot erase a dial from the observation.
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        let trap = Self {
            address,
            shutdown,
            accepted,
            handle: Some(handle),
        };
        wait_ready(accepting, setup_deadline);
        trap
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

#[derive(Debug, Default)]
struct WireReplyReport {
    requests: u64,
    sent_response_bytes: u64,
}

/// Real TCP fault injection with a fixed, signed advertisement. Truncation is
/// an exact missing last byte followed by EOF, not a scheduler-dependent sleep.
struct WireBootstrap {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<io::Result<WireReplyReport>>>,
}

impl WireBootstrap {
    fn start(
        pin: CellDiscoveryRequestV1,
        record: Vec<u8>,
        truncate: bool,
        setup_deadline: Instant,
    ) -> Self {
        assert_eq!(record.len(), CELL_PROVIDER_RECORD_BYTES_V1);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = shutdown.clone();
        let (ready, accepting) = mpsc::sync_channel(1);
        let handle = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(30);
            let mut ready = Some(ready);
            let mut report = WireReplyReport::default();
            let mut expected = b"CDQ1".to_vec();
            expected.push(1);
            expected.extend(192_u16.to_be_bytes());
            expected.extend(pin.encode());
            let mut reply = b"CDS1".to_vec();
            reply.push(0);
            reply.extend((1_u32 + CELL_PROVIDER_RECORD_BYTES_V1 as u32).to_be_bytes());
            reply.push(1);
            reply.extend(record);
            if truncate {
                reply.pop();
            }
            while report.requests < 64 && Instant::now() < end {
                let accepted = listener.accept();
                if let Some(ready) = ready.take() {
                    let _ = ready.send(());
                }
                match accepted {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_millis(250)))?;
                        stream.set_write_timeout(Some(Duration::from_millis(250)))?;
                        let mut query = vec![0; expected.len()];
                        stream.read_exact(&mut query)?;
                        assert_eq!(
                            query, expected,
                            "the actual consumer queried the pinned request"
                        );
                        report.requests += 1;
                        stream.write_all(&reply)?;
                        report.sent_response_bytes += reply.len() as u64;
                        // Dropping this connected stream sends the exact EOF;
                        // all consumer request bytes have already been read.
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(report)
        });
        let server = Self {
            address,
            shutdown,
            handle: Some(handle),
        };
        wait_ready(accepting, setup_deadline);
        server
    }

    fn stop(mut self) -> WireReplyReport {
        self.shutdown.store(true, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for WireBootstrap {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn tcp_higher_sequence_cannot_hide_observed_earlier_sequence_equivocation() {
    let setup_deadline = deadline();
    let temp = tempfile::tempdir().unwrap();
    let (manifest, _bytes, _source) = fixture(temp.path());
    let a = SilentTrap::start(setup_deadline);
    let c = SilentTrap::start(setup_deadline);
    let b = SilentTrap::start(setup_deadline);
    let endpoints = [a.address, c.address, b.address];
    let first = Rendezvous::start(
        &temp.path().join("a-rendezvous.sqlite"),
        &endpoints,
        setup_deadline,
    );
    let second = Rendezvous::start(
        &temp.path().join("c-rendezvous.sqlite"),
        &endpoints,
        setup_deadline,
    );
    let third = Rendezvous::start(
        &temp.path().join("b-rendezvous.sqlite"),
        &endpoints,
        setup_deadline,
    );
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
    let (result, observation) = super::transport::fetch_discovered_cell_to_file_observed(
        &consumer,
        &directory,
        &options,
        limits(),
        deadline(),
        &output,
    );
    eprintln!(
        "cell_equivocation success={} discovery={observation:?}",
        result.is_ok()
    );
    assert!(matches!(
        result,
        Err(CellErrorV1::Invalid("discovery has no admissible provider"))
    ));
    assert!(!output.exists());
    // A generic failed fetch is insufficient: the old implementation fails
    // only after actually dialing C. The fixed implementation rejects the
    // equivocated owner during discovery, before dialing any of its endpoints.
    let dials = [a.stop(), c.stop(), b.stop()];
    for served in [first.stop(), second.stop(), third.stop()] {
        eprintln!("cell_equivocation server={served:?}");
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
    assert_eq!(
        observation,
        CellDiscoveryObservationV1 {
            connection_attempts: 6,
            received_response_bytes: 6 * (10 + CELL_PROVIDER_RECORD_BYTES_V1) as u64,
            record_validation_attempts: 6,
            rejected_records: 4,
            capacity_rejections: 0,
            rejected_bootstraps: 0,
        },
        "zero-dial acceptance requires complete receipt and verification of both original rounds"
    );
    assert_eq!(dials, [0, 0, 0], "A(seq1), C(seq2), B(seq1) equivocation must exclude this owner before any actual provider TCP dial");
}

#[derive(Clone, Copy, Debug)]
enum WireEvidenceCase {
    CompleteConflict,
    TruncatedFirst,
    TruncatedConflict,
    InvalidConflictSignature,
}

fn check_wire_evidence(case: WireEvidenceCase) {
    let setup_deadline = deadline();
    let temp = tempfile::tempdir().unwrap();
    let (manifest, _bytes, _source) = fixture(temp.path());
    let a = SilentTrap::start(setup_deadline);
    let c = SilentTrap::start(setup_deadline);
    let b = SilentTrap::start(setup_deadline);
    let pin = request(manifest.id());
    let now = wall_now().unwrap().as_secs();
    let first_record = record(pin, a.address, 1, now, 300);
    let higher_record = record(pin, c.address, 2, now, 300);
    let conflict_record = record(pin, b.address, 1, now, 300);
    let mut conflict_wire = conflict_record.encode();
    if matches!(case, WireEvidenceCase::InvalidConflictSignature) {
        *conflict_wire.last_mut().unwrap() ^= 1;
        let invalid = CellProviderRecordV1::decode(&conflict_wire).unwrap();
        assert!(invalid
            .verify_at(pin, now, &policy(&[a.address, c.address, b.address]))
            .is_err());
    }
    let first = WireBootstrap::start(
        pin,
        first_record.encode(),
        matches!(case, WireEvidenceCase::TruncatedFirst),
        setup_deadline,
    );
    let second = WireBootstrap::start(pin, higher_record.encode(), false, setup_deadline);
    let third = WireBootstrap::start(
        pin,
        conflict_wire,
        matches!(case, WireEvidenceCase::TruncatedConflict),
        setup_deadline,
    );
    let options = CellDiscoveryOptionsV1 {
        request: pin,
        bootstraps: vec![first.address, second.address, third.address],
        addresses: policy(&[
            a.address,
            c.address,
            b.address,
            first.address,
            second.address,
            third.address,
        ]),
    };
    let consumer = CellStoreV1::open(&temp.path().join("consumer.sqlite"), cache_config()).unwrap();
    let directory =
        CellProviderDirectoryV1::open(&temp.path().join("consumer-directory.sqlite"), context())
            .unwrap();
    let output = temp.path().join("must-not-publish");
    let (result, observation) = super::transport::fetch_discovered_cell_to_file_observed(
        &consumer,
        &directory,
        &options,
        limits(),
        deadline(),
        &output,
    );
    let dials = [a.stop(), c.stop(), b.stop()];
    let servers = [first.stop(), second.stop(), third.stop()];
    eprintln!("cell_equivocation_wire case={case:?} success={} discovery={observation:?} dials={dials:?} servers={servers:?}", result.is_ok());
    assert!(result.is_err());
    assert!(
        !output.exists(),
        "no provider supplies a manifest or model payload"
    );
    let full_reply_bytes = (10 + CELL_PROVIDER_RECORD_BYTES_V1) as u64;
    let (rounds, validations, rejected, rejected_bootstraps, truncated_bytes, expected_dials) =
        match case {
            WireEvidenceCase::CompleteConflict => (2, 6, 4, 0, 0, [0, 0, 0]),
            WireEvidenceCase::TruncatedFirst => (1, 2, 1, 1, 1, [0, 1, 0]),
            WireEvidenceCase::TruncatedConflict => (1, 2, 0, 1, 1, [0, 1, 0]),
            WireEvidenceCase::InvalidConflictSignature => (1, 3, 1, 0, 0, [0, 1, 0]),
        };
    assert_eq!(
        observation,
        CellDiscoveryObservationV1 {
            connection_attempts: 3 * rounds,
            received_response_bytes: 3 * rounds * full_reply_bytes - truncated_bytes,
            record_validation_attempts: validations,
            rejected_records: rejected,
            capacity_rejections: 0,
            rejected_bootstraps,
        }
    );
    assert_eq!(dials, expected_dials);
    for server in &servers {
        assert_eq!(
            server.requests, rounds,
            "all three servers really received each query"
        );
    }
    assert_eq!(
        servers.iter().map(|s| s.sent_response_bytes).sum::<u64>(),
        observation.received_response_bytes
    );
    assert_eq!(
        directory
            .records(pin, wall_now().unwrap().as_secs(), deadline())
            .unwrap(),
        vec![higher_record]
    );
    if matches!(case, WireEvidenceCase::CompleteConflict) {
        assert!(matches!(
            result,
            Err(CellErrorV1::Invalid("discovery has no admissible provider"))
        ));
    }
}

#[test]
fn tcp_complete_conflict_receipts_exclude_owner_before_any_provider_dial() {
    check_wire_evidence(WireEvidenceCase::CompleteConflict);
}

#[test]
fn tcp_truncated_first_reply_does_not_establish_observed_equivocation() {
    check_wire_evidence(WireEvidenceCase::TruncatedFirst);
}

#[test]
fn tcp_truncated_conflict_reply_does_not_establish_observed_equivocation() {
    check_wire_evidence(WireEvidenceCase::TruncatedConflict);
}

#[test]
fn tcp_invalid_signature_cannot_turn_received_bytes_into_equivocation() {
    check_wire_evidence(WireEvidenceCase::InvalidConflictSignature);
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
