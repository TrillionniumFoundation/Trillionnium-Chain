//! Regression controls for the actual bounded rendezvous, including its reply
//! selection and native signing/verification accounting. Every lookup below
//! uses real TCP and the same original client deadline/counters for both reads.

use super::auth::{MAX_REPLY_BYTES, RESPONSE_OVERHEAD};
use super::*;
use crate::cell::{
    network::{RequestContext, ResponseBudget},
    pq::CellPqKeyPinV2,
};
use std::{
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn request() -> CellDiscoveryRequestV1 {
    CellDiscoveryRequestV1 {
        context: CellDiscoveryContextV1 {
            namespace: [71; 32],
            network: [72; 32],
            parameters: [73; 32],
            genesis: [74; 32],
        },
        cell_context: [75; 32],
        manifest: [76; 32],
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

fn fixture_clock() -> u64 {
    let now = wall_now().unwrap().as_secs();
    let remaining =
        CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3 - now % CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3;
    // Preparation may wait for a fresh epoch. Once a lookup starts, neither
    // its deadline nor the signed window is refreshed or extended.
    if remaining < 20 {
        thread::sleep(Duration::from_secs(remaining) + Duration::from_millis(20));
    }
    wall_now().unwrap().as_secs()
}

fn record(
    key: &PqNativeSigningKey,
    endpoint: SocketAddr,
    clock: u64,
    withdrawn: bool,
) -> CellProviderRecordV3 {
    let epoch = clock / CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3;
    CellProviderRecordV3::sign(
        CellProviderStatementV3 {
            request: request(),
            owner: key.public_key_id(),
            owner_generation: 1,
            endpoint,
            sequence: if withdrawn { 2 } else { 1 },
            lease_epoch: epoch,
            issued_unix_seconds: clock,
            expires_unix_seconds: (clock + 120)
                .min((epoch + 1) * CELL_DISCOVERY_LEASE_EPOCH_SECONDS_V3),
            withdrawn,
        },
        key,
    )
    .unwrap()
}

fn policy(endpoints: &[SocketAddr]) -> CellDiscoveryAddressPolicyV1 {
    let mut ports: Vec<_> = endpoints.iter().map(SocketAddr::port).collect();
    ports.sort_unstable();
    ports.dedup();
    CellDiscoveryAddressPolicyV1::LoopbackDevOnly { ports }
}

fn admit(directory: &CellProviderDirectoryV3, records: &[CellProviderRecordV3]) {
    let addresses = policy(
        &records
            .iter()
            .map(|record| record.statement.endpoint)
            .collect::<Vec<_>>(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    for record in records {
        let now = wall_now().unwrap().as_secs();
        record
            .verify_at(request(), now, &addresses, directory.keys())
            .unwrap();
        directory
            .accept_verified(record, "127.0.0.1".parse().unwrap(), now, deadline)
            .unwrap();
    }
}

type ServerResult = CellResultV1<(CellRendezvousReportV3, CellProviderDirectoryUsageV3)>;

struct Server {
    options: CellDiscoveryOptionsV3,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<ServerResult>>,
}

impl Server {
    fn start(directory: CellProviderDirectoryV3, providers: &[SocketAddr]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (key, authority) = key_and_pin(92);
        let pin = CellBootstrapPinV3 {
            endpoint: listener.local_addr().unwrap(),
            key_id: authority.key_id,
            generation: authority.generation,
        };
        let keys = CellPqKeyPinsV2::new(vec![authority]).unwrap();
        let signer = CellBootstrapSignerV3::new(pin, key, keys.clone()).unwrap();
        let mut endpoints = providers.to_vec();
        endpoints.push(pin.endpoint);
        let addresses = policy(&endpoints);
        let options = CellDiscoveryOptionsV3 {
            request: request(),
            bootstraps: vec![pin],
            bootstrap_keys: keys,
            addresses: addresses.clone(),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let report = serve_cell_rendezvous_pq_v3(
                &listener,
                &directory,
                &signer,
                &addresses,
                &shutdown,
                CellRendezvousLimitsV3 {
                    request_timeout: Duration::from_secs(2),
                    lifetime: Duration::from_secs(12),
                    max_connections: 2,
                },
            )?;
            Ok((report, directory.usage()?))
        });
        Self {
            options,
            stop,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> (CellRendezvousReportV3, CellProviderDirectoryUsageV3) {
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn query_twice(
    server: &Server,
    client: &CellProviderDirectoryV3,
    expected_records: &[CellProviderRecordV3],
    expected_provider: SocketAddr,
) {
    let requests_left = AtomicU64::new(2);
    let bytes =
        2 * (RESPONSE_OVERHEAD + 1 + expected_records.len() * CELL_PROVIDER_RECORD_BYTES_V3) as u64;
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
    // exchange returns a body only after authenticating a status-0 response.
    // Inspect the actual server order before client-side provider filtering.
    let reply = transport::exchange(
        server.options.bootstraps[0],
        &server.options.bootstrap_keys,
        1,
        &request().encode(),
        MAX_REPLY_BYTES,
        &transport,
        &mut observed,
    )
    .expect("rendezvous must return authenticated status 0, not signed denial");
    assert_eq!(usize::from(reply.body[0]), expected_records.len());
    let records: Vec<_> = reply.body[1..]
        .chunks_exact(CELL_PROVIDER_RECORD_BYTES_V3)
        .map(|wire| CellProviderRecordV3::decode(wire).unwrap())
        .collect();
    assert!(
        records == expected_records,
        "unexpected rendezvous records; actual (owner, withdrawn) order: {:?}",
        records
            .iter()
            .map(|record| (record.statement.owner, record.statement.withdrawn))
            .collect::<Vec<_>>()
    );
    let (selected, expiry) =
        transport::discover(client, &server.options, &transport, &mut observed)
            .expect("a later active provider must remain discoverable");
    assert_eq!(selected, vec![expected_provider]);
    assert!(expiry <= overall);
    assert_eq!(requests_left.load(Ordering::Relaxed), 0);
    assert_eq!(observed.connection_attempts, 2);
    assert_eq!(observed.bootstrap_validation_attempts, 2);
    assert_eq!(observed.authenticated_bootstrap_responses, 2);
    assert_eq!(observed.record_validation_attempts, expected_records.len());
    assert_eq!(observed.rejected_bootstraps, 0);
    assert_eq!(observed.rejected_records, 0);
    assert_eq!(observed.capacity_rejections, 0);
    assert_eq!(observed.received_response_bytes, bytes);
    assert_eq!(responses.received().unwrap(), bytes);
}

#[test]
fn real_tcp_rendezvous_skips_expired_or_revoked_key_while_record_ttl_is_live() {
    for revoked in [false, true] {
        let mut signers: Vec<_> = (61..=62).map(key_and_pin).collect();
        signers.sort_by_key(|(_, pin)| pin.key_id);
        let clock = fixture_clock();
        let cutoff = clock + 4;
        if revoked {
            signers[0].1.revoked_at = Some(cutoff);
        } else {
            signers[0].1.expires_at = cutoff;
        }
        let keys =
            CellPqKeyPinsV2::new(signers.iter().map(|(_, pin)| pin.clone()).collect()).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let directory = CellProviderDirectoryV3::open(
            &tmp.path().join("server"),
            request().context,
            keys.clone(),
        )
        .unwrap();
        let endpoints: Vec<SocketAddr> = ["127.0.0.1:18000", "127.0.1.1:18000"]
            .iter()
            .map(|endpoint| endpoint.parse().unwrap())
            .collect();
        let records: Vec<_> = signers
            .iter()
            .zip(&endpoints)
            .map(|((key, _), endpoint)| {
                record(key, *endpoint, wall_now().unwrap().as_secs(), false)
            })
            .collect();
        assert!(records[0].statement.owner < records[1].statement.owner);
        admit(&directory, &records);
        let wait_deadline = Instant::now() + Duration::from_secs(6);
        while wall_now().unwrap().as_secs() < cutoff {
            assert!(
                Instant::now() < wait_deadline,
                "fixture key-expiry wait exceeded bound"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let query_clock = wall_now().unwrap().as_secs();
        // Otherwise a passing test could merely have filtered an expired CDP3
        // statement or retired its epoch, without exercising authority expiry.
        assert!(records[0].live_at(query_clock).is_ok());
        assert!(records[1].live_at(query_clock).is_ok());
        assert!(signers[0].1.live_at(query_clock).is_err());
        assert!(signers[1].1.live_at(query_clock).is_ok());
        let client =
            CellProviderDirectoryV3::open(&tmp.path().join("client"), request().context, keys)
                .unwrap();
        let server = Server::start(directory, &endpoints);
        query_twice(&server, &client, &records[1..], endpoints[1]);
        let (report, usage) = server.finish();
        assert_eq!(report.connections, 2);
        assert_eq!(report.rejected_requests, 0);
        assert_eq!(report.record_validation_attempts, 2);
        assert_eq!(report.response_signing_attempts, 2);
        assert_eq!(
            report.record_validation_attempts + 2 * report.response_signing_attempts,
            6
        );
        assert_eq!(usage.retained_identities, 2);
        assert_eq!(usage.active_identities, 1);
        assert_eq!(usage.tombstone_identities, 1);
        assert_eq!(client.usage().unwrap().retained_identities, 1);
    }
}

#[test]
fn real_tcp_rendezvous_prioritizes_ninth_active_provider_over_eight_withdrawn_rows() {
    let mut signers: Vec<_> = (1..=9).map(key_and_pin).collect();
    signers.sort_by_key(|(_, pin)| pin.key_id);
    let clock = fixture_clock();
    let keys = CellPqKeyPinsV2::new(signers.iter().map(|(_, pin)| pin.clone()).collect()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let directory =
        CellProviderDirectoryV3::open(&tmp.path().join("server"), request().context, keys.clone())
            .unwrap();
    let endpoints: Vec<_> = (0..9)
        .map(|index| SocketAddr::from(([127, 0, u8::from(index == 8), 1], 18000 + index)))
        .collect();
    let records: Vec<_> = signers
        .iter()
        .zip(&endpoints)
        .enumerate()
        .map(|(index, ((key, _), endpoint))| record(key, *endpoint, clock, index < 8))
        .collect();
    admit(&directory, &records);
    let mut expected = vec![records[8].clone()];
    expected.extend_from_slice(&records[..7]);
    let client =
        CellProviderDirectoryV3::open(&tmp.path().join("client"), request().context, keys).unwrap();
    let server = Server::start(directory, &endpoints);
    query_twice(&server, &client, &expected, endpoints[8]);
    let (report, usage) = server.finish();
    assert_eq!(report.connections, 2);
    assert_eq!(report.rejected_requests, 0);
    assert_eq!(report.record_validation_attempts, 16);
    assert_eq!(report.response_signing_attempts, 2);
    assert_eq!(
        report.record_validation_attempts + 2 * report.response_signing_attempts,
        20
    );
    assert_eq!(usage.retained_identities, 9);
    assert_eq!(usage.active_identities, 1);
    assert_eq!(usage.tombstone_identities, 8);
    let client_usage = client.usage().unwrap();
    assert_eq!(client_usage.retained_identities, 8);
    assert_eq!(client_usage.active_identities, 1);
    assert_eq!(client_usage.tombstone_identities, 7);
}
