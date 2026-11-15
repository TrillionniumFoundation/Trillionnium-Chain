//! Actual TCP replies, real signatures and durable high-water admission. The
//! endpoints are bounded location hints; these tests do not claim custody.

use super::super::network::{RequestContext, ResponseBudget};
use super::*;
use std::{
    io::{self, Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
};

pub(super) struct WireBootstrap {
    pub address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<bool>>,
}

impl WireBootstrap {
    pub fn start(version: u8, records: Vec<Vec<u8>>) -> Self {
        Self::start_after(version, records, None)
    }

    /// Hold a response until an actual wall-clock boundary. The late source
    /// must first receive its query before that boundary, proving the earlier
    /// sequential sources were received while their short leases were live.
    pub fn start_after(version: u8, records: Vec<Vec<u8>>, not_before: Option<u64>) -> Self {
        assert!((1..=MAX_DISCOVERED_PROVIDERS).contains(&records.len()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(10);
            while Instant::now() < end && !cancelled.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut header = [0; 7];
                        stream.read_exact(&mut header).unwrap();
                        assert_eq!(header, [b'C', b'D', b'Q', version, 1, 0, 192]);
                        let mut request = [0; 192];
                        stream.read_exact(&mut request).unwrap();
                        CellDiscoveryRequestV1::decode(&request).unwrap();
                        let mut body = vec![records.len() as u8];
                        for record in records {
                            body.extend(record);
                        }
                        let mut reply = vec![b'C', b'D', b'S', version, 0];
                        reply.extend((body.len() as u32).to_be_bytes());
                        reply.extend(body);
                        if let Some(not_before) = not_before {
                            assert!(
                                wall_now().unwrap().as_secs() < not_before,
                                "fixture: early replies must arrive before their original expiry"
                            );
                            while wall_now().unwrap().as_secs() < not_before {
                                if Instant::now() >= end || cancelled.load(Ordering::Relaxed) {
                                    return false;
                                }
                                thread::sleep(Duration::from_millis(1));
                            }
                        }
                        stream.write_all(&reply).unwrap();
                        return true;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                    Err(error) => panic!("bootstrap listener: {error}"),
                }
            }
            false
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }

    pub fn finish(mut self) {
        assert!(self.worker.take().unwrap().join().unwrap());
    }
}

impl Drop for WireBootstrap {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(super) fn provider_endpoints() -> Vec<SocketAddr> {
    // Eight owners/ports at one IP precede a ninth owner from a later directory.
    (0..9)
        .map(|index| SocketAddr::from(([127, 0, u8::from(index == 8), 1], 18000 + index)))
        .collect()
}

pub(super) fn saturation_endpoints() -> Vec<SocketAddr> {
    // Sixteen identities from the first two sources fill the manifest's entire
    // permanent quota in the old source-at-a-time admission order. Reuse one
    // service port so this counterexample stays inside the original address
    // policy's sixteen-port cap. The seventeenth identity is a later source.
    (1..=17)
        .map(|index| {
            let ip = if index == 17 {
                [127, 0, 1, 1]
            } else {
                [127, 0, 0, index]
            };
            SocketAddr::from((ip, 18000))
        })
        .collect()
}

pub(super) fn scoped_ports(peers: &[SocketAddr]) -> CellDiscoveryAddressPolicyV1 {
    let mut ports: Vec<_> = peers.iter().map(SocketAddr::port).collect();
    ports.sort_unstable();
    ports.dedup();
    let policy = CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports };
    policy.validate().unwrap();
    policy
}

#[test]
fn real_tcp_low_owner_flood_keeps_later_bootstrap_provider_and_original_budgets() {
    let temp = tempfile::tempdir().unwrap();
    let context = CellDiscoveryContextV1 {
        namespace: [41; 32],
        network: [42; 32],
        parameters: [43; 32],
        genesis: [44; 32],
    };
    let request = CellDiscoveryRequestV1 {
        context,
        cell_context: [45; 32],
        manifest: [46; 32],
    };
    let directory = CellProviderDirectoryV1::open(&temp.path().join("directory"), context).unwrap();
    let now = wall_now().unwrap().as_secs();
    let endpoints = provider_endpoints();
    let mut keys: Vec<_> = (1..=9)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect();
    keys.sort_by_key(|key| key.verifying_key().to_bytes());
    let records: Vec<_> = keys
        .iter()
        .zip(&endpoints)
        .map(|(key, endpoint)| {
            CellProviderRecordV1::sign(
                CellProviderStatementV1 {
                    request,
                    owner: key.verifying_key().to_bytes(),
                    endpoint: *endpoint,
                    sequence: 1,
                    issued_unix_seconds: now,
                    expires_unix_seconds: now + 240,
                },
                key,
            )
            .unwrap()
            .encode()
        })
        .collect();
    let first = WireBootstrap::start(b'1', records[..8].to_vec());
    let later = WireBootstrap::start(b'1', records[8..].to_vec());
    let mut allowed = endpoints.clone();
    allowed.extend([first.address, later.address]);
    let options = CellDiscoveryOptionsV1 {
        request,
        bootstraps: vec![first.address, later.address],
        addresses: scoped_ports(&allowed),
    };
    let requests_left = AtomicU64::new(2);
    let bytes = 2 * 10 + 9 * CELL_PROVIDER_RECORD_BYTES_V1 as u64;
    let responses = ResponseBudget::new(bytes);
    let overall = Instant::now() + Duration::from_secs(10);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall,
        requests_left: &requests_left,
        responses: &responses,
    };
    let mut observed = CellDiscoveryObservationV1::default();
    let (selected, expiry) =
        transport::discover(&directory, &options, &transport, &mut observed).unwrap();
    assert_eq!(selected.len(), 8);
    assert_eq!(selected[0], endpoints[0]);
    assert_eq!(selected[1], endpoints[8]);
    assert!(expiry <= overall);
    assert_eq!(observed.connection_attempts, 2);
    assert_eq!(requests_left.load(Ordering::Relaxed), 0);
    assert_eq!(observed.record_validation_attempts, 9);
    assert_eq!(observed.rejected_records, 0);
    assert_eq!(observed.received_response_bytes, bytes);
    assert_eq!(responses.received().unwrap(), bytes);
    assert_eq!(directory.usage().unwrap().retained_identities, 9);
    first.finish();
    later.finish();
}

#[test]
fn real_tcp_manifest_quota_flood_keeps_later_source_without_resetting_highwater_or_budget() {
    let temp = tempfile::tempdir().unwrap();
    let context = CellDiscoveryContextV1 {
        namespace: [51; 32],
        network: [52; 32],
        parameters: [53; 32],
        genesis: [54; 32],
    };
    let request = CellDiscoveryRequestV1 {
        context,
        cell_context: [55; 32],
        manifest: [56; 32],
    };
    let path = temp.path().join("directory");
    let directory = CellProviderDirectoryV1::open(&path, context).unwrap();
    let now = wall_now().unwrap().as_secs();
    let endpoints = saturation_endpoints();
    let mut keys: Vec<_> = (1..=17)
        .map(|seed| SigningKey::from_bytes(&[seed; 32]))
        .collect();
    keys.sort_by_key(|key| key.verifying_key().to_bytes());
    let records: Vec<_> = keys
        .iter()
        .zip(&endpoints)
        .map(|(key, endpoint)| {
            CellProviderRecordV1::sign(
                CellProviderStatementV1 {
                    request,
                    owner: key.verifying_key().to_bytes(),
                    endpoint: *endpoint,
                    sequence: 2,
                    issued_unix_seconds: now,
                    expires_unix_seconds: now + 240,
                },
                key,
            )
            .unwrap()
        })
        .collect();
    let first = WireBootstrap::start(b'1', records[..8].iter().map(|r| r.encode()).collect());
    let second = WireBootstrap::start(b'1', records[8..16].iter().map(|r| r.encode()).collect());
    let later = WireBootstrap::start(b'1', vec![records[16].encode()]);
    let mut allowed = endpoints.clone();
    allowed.extend([first.address, second.address, later.address]);
    let options = CellDiscoveryOptionsV1 {
        request,
        bootstraps: vec![first.address, second.address, later.address],
        addresses: scoped_ports(&allowed),
    };
    let requests_left = AtomicU64::new(3);
    let bytes = 3 * 10 + 17 * CELL_PROVIDER_RECORD_BYTES_V1 as u64;
    let responses = ResponseBudget::new(bytes);
    let overall = Instant::now() + Duration::from_secs(10);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(2),
        overall,
        requests_left: &requests_left,
        responses: &responses,
    };
    let mut observed = CellDiscoveryObservationV1::default();
    let (selected, expiry) =
        transport::discover(&directory, &options, &transport, &mut observed).unwrap();
    assert_eq!(selected.len(), MAX_DISCOVERED_PROVIDERS);
    assert!(expiry <= overall);
    assert_eq!(observed.connection_attempts, 3);
    assert_eq!(requests_left.load(Ordering::Relaxed), 0);
    assert_eq!(observed.record_validation_attempts, 17);
    assert_eq!(observed.capacity_rejections, 1);
    assert_eq!(observed.rejected_records, 1);
    assert_eq!(observed.received_response_bytes, bytes);
    assert_eq!(responses.received().unwrap(), bytes);
    assert_eq!(directory.usage().unwrap().retained_identities, 16);
    assert!(
        selected.contains(&endpoints[16]),
        "early source batches must not exhaust the durable quota before the later source competes"
    );
    first.finish();
    second.finish();
    later.finish();

    // The repair changes scheduling, not durable replay ownership. A cold
    // reopen keeps all sixteen identities and still rejects the honest key's
    // signed lower sequence; neither expiry nor retry creates a fresh quota.
    drop(directory);
    let reopened = CellProviderDirectoryV1::open(&path, context).unwrap();
    assert_eq!(reopened.usage().unwrap().retained_identities, 16);
    let mut stale = records[16].statement().clone();
    stale.sequence = 1;
    let stale = CellProviderRecordV1::sign(stale, &keys[16]).unwrap();
    let wall = wall_now().unwrap().as_secs();
    stale.verify_at(request, wall, &options.addresses).unwrap();
    assert!(matches!(
        reopened.accept_verified(&stale, options.bootstraps[2].ip(), wall, overall),
        Err(CellErrorV1::Invalid("discovery sequence replay"))
    ));
    assert_eq!(reopened.usage().unwrap().retained_identities, 16);
}

#[test]
fn real_tcp_receive_time_equivocation_survives_later_bootstrap_delay_and_expiry() {
    let temp = tempfile::tempdir().unwrap();
    let context = CellDiscoveryContextV1 {
        namespace: [61; 32],
        network: [62; 32],
        parameters: [63; 32],
        genesis: [64; 32],
    };
    let request = CellDiscoveryRequestV1 {
        context,
        cell_context: [65; 32],
        manifest: [66; 32],
    };
    let directory = CellProviderDirectoryV1::open(&temp.path().join("directory"), context).unwrap();
    let key = SigningKey::from_bytes(&[67; 32]);
    let endpoints = provider_endpoints();
    let now = wall_now().unwrap().as_secs();
    let short_expiry = now + 3;
    let records: Vec<_> = (0..3)
        .map(|index| {
            CellProviderRecordV1::sign(
                CellProviderStatementV1 {
                    request,
                    owner: key.verifying_key().to_bytes(),
                    endpoint: endpoints[index],
                    sequence: if index == 2 { 2 } else { 1 },
                    issued_unix_seconds: now,
                    expires_unix_seconds: if index == 2 { now + 240 } else { short_expiry },
                },
                &key,
            )
            .unwrap()
        })
        .collect();
    let first = WireBootstrap::start(b'1', vec![records[0].encode()]);
    let conflict = WireBootstrap::start(b'1', vec![records[1].encode()]);
    let later = WireBootstrap::start_after(b'1', vec![records[2].encode()], Some(short_expiry));
    let mut allowed = endpoints[..3].to_vec();
    allowed.extend([first.address, conflict.address, later.address]);
    let options = CellDiscoveryOptionsV1 {
        request,
        bootstraps: vec![first.address, conflict.address, later.address],
        addresses: scoped_ports(&allowed),
    };
    let requests_left = AtomicU64::new(3);
    let bytes = 3 * 10 + 3 * CELL_PROVIDER_RECORD_BYTES_V1 as u64;
    let responses = ResponseBudget::new(bytes);
    let overall = Instant::now() + Duration::from_secs(10);
    let transport = RequestContext {
        cancelled: None,
        timeout: Duration::from_secs(5),
        overall,
        requests_left: &requests_left,
        responses: &responses,
    };
    let mut observed = CellDiscoveryObservationV1::default();
    assert!(matches!(
        transport::discover(&directory, &options, &transport, &mut observed),
        Err(CellErrorV1::Invalid("discovery has no admissible provider"))
    ));
    assert_eq!(observed.connection_attempts, 3);
    assert_eq!(requests_left.load(Ordering::Relaxed), 0);
    assert_eq!(observed.record_validation_attempts, 3);
    assert_eq!(observed.received_response_bytes, bytes);
    assert_eq!(responses.received().unwrap(), bytes);
    assert_eq!(observed.capacity_rejections, 0);
    first.finish();
    conflict.finish();
    later.finish();
    // The later fresh high water remains durable even though this operation
    // may not use the identity after its earlier observed equivocation.
    assert_eq!(
        directory
            .records(request, wall_now().unwrap().as_secs(), overall)
            .unwrap(),
        vec![records[2].clone()]
    );
}
