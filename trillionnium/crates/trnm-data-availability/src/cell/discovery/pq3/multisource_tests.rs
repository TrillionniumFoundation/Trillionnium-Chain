//! Real native-signed TCP sources compete within one original client budget.
//! The separate keys below are test authorities on one host, not independent
//! operators, custody providers or a public-network availability measurement.

use super::auth::{self, BootstrapQueryV3, QUERY_HEADER_BYTES, RESPONSE_OVERHEAD};
use super::*;
use crate::cell::{
    network::{RequestContext, ResponseBudget},
    pq::CellPqKeyPinV2,
};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn context() -> CellDiscoveryContextV1 {
    CellDiscoveryContextV1 {
        namespace: [51; 32],
        network: [52; 32],
        parameters: [53; 32],
        genesis: [54; 32],
    }
}

fn request() -> CellDiscoveryRequestV1 {
    CellDiscoveryRequestV1 {
        context: context(),
        cell_context: [55; 32],
        manifest: [56; 32],
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

fn live_now() -> u64 {
    let now = wall_now().unwrap().as_secs();
    let remaining =
        CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3 - now % CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3;
    // This is fixture preparation only. Neither discovery nor its retries get
    // a fresh epoch/deadline after the operation has started.
    if remaining < 20 {
        thread::sleep(Duration::from_secs(remaining) + Duration::from_millis(20));
    }
    wall_now().unwrap().as_secs()
}

fn record(
    key: &PqNativeSigningKey,
    pin: &CellPqKeyPinV2,
    endpoint: SocketAddr,
    now: u64,
) -> CellProviderRecordV3 {
    let epoch = now / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3;
    CellProviderRecordV3::sign(
        CellProviderStatementV3 {
            request: request(),
            owner: pin.key_id,
            owner_generation: pin.generation,
            endpoint,
            sequence: 1,
            lease_epoch: epoch,
            issued_unix_seconds: now,
            expires_unix_seconds: (now + 120)
                .min((epoch + 1) * CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3),
            withdrawn: false,
        },
        key,
    )
    .unwrap()
}

fn read_query(stream: &mut TcpStream) -> CellResultV1<BootstrapQueryV3> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut header = [0; QUERY_HEADER_BYTES];
    stream.read_exact(&mut header)?;
    let length = auth::query_length(&header)?;
    let mut wire = header.to_vec();
    wire.resize(QUERY_HEADER_BYTES + length, 0);
    stream.read_exact(&mut wire[QUERY_HEADER_BYTES..])?;
    BootstrapQueryV3::decode(&wire)
}

struct ServedReply {
    nonce: [u8; 32],
    bytes: usize,
}

struct SignedSource {
    pin: CellBootstrapPinV3,
    authority: CellPqKeyPinV2,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<CellResultV1<ServedReply>>>,
}

impl SignedSource {
    fn start(seed: u8, records: Vec<Vec<u8>>, corrupt_origin_signature: bool) -> Self {
        assert!(records.len() <= MAX_DISCOVERED_PROVIDERS);
        assert!(records
            .iter()
            .all(|wire| wire.len() == CELL_PROVIDER_RECORD_BYTES_V3));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let (key, authority) = key_and_pin(seed);
        let pin = CellBootstrapPinV3 {
            endpoint: listener.local_addr().unwrap(),
            key_id: authority.key_id,
            generation: authority.generation,
        };
        let signer = CellBootstrapSignerV3::new(
            pin,
            key,
            CellPqKeyPinsV2::new(vec![authority.clone()]).unwrap(),
        )
        .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            while !shutdown.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let query = read_query(&mut stream)?;
                        require(query.kind == 1, "test lookup operation")?;
                        require(query.body == request().encode(), "test complete request")?;
                        let mut body = vec![records.len() as u8];
                        for record in records {
                            body.extend(record);
                        }
                        let mut response =
                            signer.sign_response(&query, 0, &body, wall_now()?.as_secs())?;
                        if corrupt_origin_signature {
                            *response.last_mut().unwrap() ^= 1;
                        }
                        stream.write_all(&response)?;
                        return Ok(ServedReply {
                            nonce: query.nonce,
                            bytes: response.len(),
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                    Err(error) => return Err(error.into()),
                }
            }
            Err(CellErrorV1::Invalid("test source stopped without a query"))
        });
        Self {
            pin,
            authority,
            stop,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> ServedReply {
        self.worker.take().unwrap().join().unwrap().unwrap()
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

fn options(
    first: &SignedSource,
    later: &SignedSource,
    endpoints: &[SocketAddr],
) -> CellDiscoveryOptionsV3 {
    let mut ports: Vec<_> = endpoints.iter().map(SocketAddr::port).collect();
    ports.extend([first.pin.endpoint.port(), later.pin.endpoint.port()]);
    ports.sort_unstable();
    ports.dedup();
    CellDiscoveryOptionsV3 {
        request: request(),
        bootstraps: vec![first.pin, later.pin],
        bootstrap_keys: CellPqKeyPinsV2::new(vec![
            first.authority.clone(),
            later.authority.clone(),
        ])
        .unwrap(),
        addresses: CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports },
    }
}

#[test]
fn real_tcp_native_low_owner_flood_keeps_later_source_before_and_after_active_quota() {
    let mut signers: Vec<_> = (1..=9).map(key_and_pin).collect();
    signers.sort_by_key(|(_, pin)| pin.key_id);
    let prior_signers: Vec<_> = (20..28).map(key_and_pin).collect();
    let pins = CellPqKeyPinsV2::new(
        signers
            .iter()
            .chain(&prior_signers)
            .map(|(_, pin)| pin.clone())
            .collect(),
    )
    .unwrap();
    let endpoints: Vec<_> = (0..9)
        .map(|index| SocketAddr::from(([127, 0, u8::from(index == 8), 1], 18000 + index)))
        .collect();
    for prior_count in [0_usize, 8] {
        let now = live_now();
        let tmp = tempfile::tempdir().unwrap();
        let directory =
            CellProviderDirectoryV3::open(&tmp.path().join("directory"), context(), pins.clone())
                .unwrap();
        let records: Vec<_> = signers
            .iter()
            .zip(&endpoints)
            .map(|((key, pin), endpoint)| record(key, pin, *endpoint, now).encode())
            .collect();
        let first = SignedSource::start(92, records[..8].to_vec(), false);
        let later = SignedSource::start(93, records[8..].to_vec(), false);
        let options = options(&first, &later, &endpoints);
        for (key, pin) in prior_signers.iter().take(prior_count) {
            let prior = record(key, pin, endpoints[0], now);
            prior
                .verify_at(request(), now, &options.addresses, directory.keys())
                .unwrap();
            directory
                .accept_verified(
                    &prior,
                    first.pin.endpoint.ip(),
                    now,
                    Instant::now() + Duration::from_secs(2),
                )
                .unwrap();
        }
        let requests_left = AtomicU64::new(2);
        let bytes = (2 * (RESPONSE_OVERHEAD + 1) + 9 * CELL_PROVIDER_RECORD_BYTES_V3) as u64;
        assert!(bytes < MAX_DISCOVERY_RESPONSE_BYTES_V3);
        let responses = ResponseBudget::new(bytes);
        let overall = Instant::now() + Duration::from_secs(10);
        let transport = RequestContext {
            cancelled: None,
            timeout: Duration::from_secs(2),
            overall,
            requests_left: &requests_left,
            responses: &responses,
        };
        let mut observed = CellDiscoveryObservationV3::default();
        let (selected, expiry) =
            transport::discover(&directory, &options, &transport, &mut observed).unwrap();
        assert_eq!(selected.len(), MAX_DISCOVERED_PROVIDERS);
        assert_eq!(selected[0], endpoints[0]);
        assert_eq!(selected[1], endpoints[8]);
        assert!(expiry <= overall);
        assert_eq!(observed.connection_attempts, 2);
        assert_eq!(requests_left.load(Ordering::Relaxed), 0);
        assert_eq!(observed.bootstrap_validation_attempts, 2);
        assert_eq!(observed.authenticated_bootstrap_responses, 2);
        assert_eq!(observed.record_validation_attempts, 9);
        assert_eq!(observed.rejected_bootstraps, 0);
        let rejected = usize::from(prior_count != 0);
        assert_eq!(observed.rejected_records, rejected);
        assert_eq!(observed.capacity_rejections, rejected);
        assert_eq!(observed.received_response_bytes, bytes);
        assert_eq!(responses.received().unwrap(), bytes);
        let usage = directory.usage().unwrap();
        assert_eq!(
            usage.retained_identities,
            (prior_count + 9 - rejected) as u64
        );
        assert_eq!(usage.active_identities, usage.retained_identities);
        let first = first.finish();
        let later = later.finish();
        assert_ne!(first.nonce, later.nonce);
        assert_eq!((first.bytes + later.bytes) as u64, bytes);
    }
}

#[test]
fn real_tcp_malicious_first_source_cannot_overwrite_later_authenticated_provider() {
    let (key, pin) = key_and_pin(42);
    let endpoint: SocketAddr = "127.0.1.1:18000".parse().unwrap();
    for corrupt_origin_signature in [false, true] {
        let now = live_now();
        let tmp = tempfile::tempdir().unwrap();
        let directory = CellProviderDirectoryV3::open(
            &tmp.path().join("directory"),
            context(),
            CellPqKeyPinsV2::new(vec![pin.clone()]).unwrap(),
        )
        .unwrap();
        let valid = record(&key, &pin, endpoint, now);
        let forged: Vec<_> = (0..8)
            .map(|index| {
                let mut forged = valid.clone();
                // The source controls its own signing key, not this provider's.
                // Canonical higher-sequence forgeries must not reach high water.
                forged.statement.sequence = 100 + index;
                forged.statement.withdrawn = true;
                forged.encode()
            })
            .collect();
        let first = SignedSource::start(92, forged, corrupt_origin_signature);
        let later = SignedSource::start(93, vec![valid.encode()], false);
        let options = options(&first, &later, &[endpoint]);
        let requests_left = AtomicU64::new(2);
        let bytes = (2 * (RESPONSE_OVERHEAD + 1) + 9 * CELL_PROVIDER_RECORD_BYTES_V3) as u64;
        let responses = ResponseBudget::new(bytes);
        let overall = Instant::now() + Duration::from_secs(10);
        let transport = RequestContext {
            cancelled: None,
            timeout: Duration::from_secs(2),
            overall,
            requests_left: &requests_left,
            responses: &responses,
        };
        let mut observed = CellDiscoveryObservationV3::default();
        let (selected, expiry) =
            transport::discover(&directory, &options, &transport, &mut observed).unwrap();
        assert_eq!(selected, vec![endpoint]);
        assert!(expiry <= overall);
        assert_eq!(observed.connection_attempts, 2);
        assert_eq!(requests_left.load(Ordering::Relaxed), 0);
        assert_eq!(observed.bootstrap_validation_attempts, 2);
        assert_eq!(
            observed.authenticated_bootstrap_responses,
            if corrupt_origin_signature { 1 } else { 2 }
        );
        assert_eq!(
            observed.rejected_bootstraps,
            usize::from(corrupt_origin_signature)
        );
        assert_eq!(
            observed.record_validation_attempts,
            if corrupt_origin_signature { 1 } else { 9 }
        );
        assert_eq!(
            observed.rejected_records,
            if corrupt_origin_signature { 0 } else { 8 }
        );
        assert_eq!(observed.capacity_rejections, 0);
        assert_eq!(observed.received_response_bytes, bytes);
        assert_eq!(responses.received().unwrap(), bytes);
        assert_eq!(directory.usage().unwrap().retained_identities, 1);
        assert_eq!(
            directory
                .records(request(), wall_now().unwrap().as_secs(), overall)
                .unwrap(),
            vec![valid]
        );
        let first = first.finish();
        let later = later.finish();
        assert_ne!(first.nonce, later.nonce);
        assert_eq!((first.bytes + later.bytes) as u64, bytes);
    }
}
