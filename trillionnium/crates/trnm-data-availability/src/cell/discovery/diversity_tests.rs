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
