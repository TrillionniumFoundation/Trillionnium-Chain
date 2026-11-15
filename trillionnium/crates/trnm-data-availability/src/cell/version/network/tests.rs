use super::*;
use crate::cell::{
    serve_cells_bounded_with_availability_and_ready, serve_cells_bounded_with_ready,
    serve_cells_persistent_rarest_first_with_ready, serve_cells_persistent_with_ready,
    CellCacheConfigV4, CellFileRoleV1, CellLoaderContextV1, CellPeerLimitsV1,
    CellPersistentServeLimitsV2, CellReleaseLimitsV1, CellServeLimitsV1, CellServeReportV1,
};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{atomic::Ordering, mpsc, Arc},
    thread::{self, JoinHandle},
    time::Duration,
};

struct Fixture {
    directory: tempfile::TempDir,
    source: CellStoreV1,
    version: CellVersionManifestV1,
    model: CellLoaderContextV1,
    environment: CellLoaderContextV1,
}

impl Fixture {
    fn new() -> Self {
        let (directory, source, version) = super::super::tests::fixture();
        let mut model = super::super::tests::owner(version.model().closure(), CellFileRoleV1::Base);
        model.required_roles.push(CellFileRoleV1::Tokenizer);
        let environment =
            super::super::tests::owner(version.environment(), CellFileRoleV1::Configuration);
        Self {
            directory,
            source,
            version,
            model,
            environment,
        }
    }

    fn expected(&self) -> CellVersionLoaderContextV1<'_> {
        CellVersionLoaderContextV1 {
            commitment: self.version.commitment(),
            model: &self.model,
            environment: &self.environment,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn cache(&self, name: &str) -> CellStoreV1 {
        CellStoreV1::open(
            &self.path(name),
            CellCacheConfigV4 {
                max_database_bytes: 64 << 20,
                max_logical_bytes: 32 << 20,
                max_chunk_rows: 128,
                max_manifest_rows: 64,
            },
        )
        .unwrap()
    }

    fn copy_member(&self, target: &CellStoreV1, member: &CellManifestV1, payload: bool) {
        target.put_manifest(member.id(), &member.encode()).unwrap();
        if payload {
            for chunk in member.chunks() {
                target
                    .put_chunk(chunk, &self.source.chunk(chunk.sha256).unwrap().unwrap())
                    .unwrap();
            }
        }
    }

    fn response_bytes(&self) -> u64 {
        self.version
            .manifests()
            .iter()
            .map(member_response_bytes)
            .sum()
    }

    fn fetch(
        &self,
        receiver: &CellStoreV1,
        peers: &[SocketAddr],
        options: CellReleaseFetchOptionsV2,
        cancelled: Option<&AtomicBool>,
    ) -> Result<CellVersionFetchObservationV1, CellVersionFetchFailureV1> {
        fetch_complete_version(
            receiver,
            &self.version,
            &self.expected(),
            peers,
            options,
            cancelled,
        )
    }
}

fn member_response_bytes(member: &CellManifestV1) -> u64 {
    member.encode().len() as u64 + member.size() + 9 * (1 + member.chunks().len() as u64)
}

fn options(profile: CellFetchTransportV2) -> CellReleaseFetchOptionsV2 {
    CellReleaseFetchOptionsV2 {
        limits: CellReleaseFetchLimitsV1 {
            peer: CellPeerLimitsV1 {
                request_timeout: Duration::from_secs(3),
                overall_timeout: Duration::from_secs(10),
                max_cell_bytes: 1_000_000,
                parallelism: 1,
                max_connections: 256,
                max_response_bytes: 2_000_000,
            },
            release: CellReleaseLimitsV1 {
                max_payload_bytes: 1_000_000,
                max_chunks: 64,
                deadline: Instant::now() + Duration::from_secs(10),
            },
        },
        transport: profile,
    }
}

fn persistent(requests: u64) -> CellFetchTransportV2 {
    CellFetchTransportV2::PersistentV2 {
        max_requests: requests,
        max_requests_per_connection: requests,
    }
}

const PROFILES: [CellFetchTransportV2; 4] = [
    CellFetchTransportV2::OrderedV1,
    CellFetchTransportV2::RarestFirstV1,
    CellFetchTransportV2::PersistentV2 {
        max_requests: 256,
        max_requests_per_connection: 256,
    },
    CellFetchTransportV2::PersistentRarestFirstV3 {
        max_requests: 256,
        max_requests_per_connection: 256,
    },
];

struct Provider {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<CellResultV1<CellServeReportV1>>>,
}

impl Provider {
    fn start(path: &Path, profile: CellFetchTransportV2) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&shutdown);
        let path = path.to_owned();
        let (ready, receiver) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let serving = CellServeLimitsV1 {
                request_timeout: Duration::from_secs(5),
                overall_timeout: Duration::from_secs(15),
                max_workers: 2,
                max_connections: 512,
                max_response_bytes: 4_000_000,
            };
            let limits = CellPersistentServeLimitsV2 {
                serving,
                max_requests: 512,
                max_requests_per_connection: 512,
            };
            let ready = || {
                ready
                    .send(())
                    .map_err(|_| CellErrorV1::Invalid("version test readiness receiver"))
            };
            match profile {
                CellFetchTransportV2::OrderedV1 => {
                    serve_cells_bounded_with_ready(&listener, &path, &stop, serving, &ready)
                }
                CellFetchTransportV2::RarestFirstV1 => {
                    serve_cells_bounded_with_availability_and_ready(
                        &listener, &path, &stop, serving, &ready,
                    )
                }
                CellFetchTransportV2::PersistentV2 { .. } => {
                    serve_cells_persistent_with_ready(&listener, &path, &stop, limits, &ready)
                        .map(|report| report.serving)
                }
                CellFetchTransportV2::PersistentRarestFirstV3 { .. } => {
                    serve_cells_persistent_rarest_first_with_ready(
                        &listener, &path, &stop, limits, &ready,
                    )
                    .map(|report| report.serving)
                }
            }
        });
        receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            address,
            shutdown,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> CellServeReportV1 {
        self.shutdown.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn assert_no_network(transport: &CellVersionFetchTransportReportV1, listener: &TcpListener) {
    assert_eq!(transport.connection_attempts, 0);
    assert_eq!(transport.request_attempts, 0);
    assert_eq!(transport.received_response_bytes, Some(0));
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn complete_version_recovers_split_model_and_environment_from_real_tcp_peers() {
    let fixture = Fixture::new();
    for (run, profile) in PROFILES.into_iter().enumerate() {
        let mut providers = Vec::new();
        for partition in 0..3 {
            let name = format!("partition-{run}-{partition}.sqlite");
            let store = fixture.cache(&name);
            for member in fixture
                .version
                .manifests()
                .iter()
                .skip(partition)
                .step_by(3)
            {
                fixture.copy_member(&store, member, true);
            }
            assert!(fixture
                .version
                .verify_cached(&store, &fixture.expected(), options(profile).limits.release)
                .is_err());
            drop(store);
            providers.push(Provider::start(&fixture.path(&name), profile));
        }
        let peers: Vec<_> = providers.iter().map(|provider| provider.address).collect();
        let receiver = fixture.cache(&format!("receiver-{run}.sqlite"));
        let report = fixture
            .fetch(&receiver, &peers, options(profile), None)
            .unwrap();
        assert_eq!(report.readback().commitment, fixture.version.commitment());
        assert_eq!(report.readback().model_root, fixture.version.model().id());
        assert_eq!(
            report.readback().environment_closure,
            fixture.version.environment().id()
        );
        assert_eq!(report.readback().manifests, 4);
        assert_eq!(report.readback().payload_bytes, 4 * 32769);
        assert_eq!(report.readback().chunks, 12);
        assert_eq!(report.cached_chunks(), 0);
        assert_eq!(report.downloaded_chunks(), 12);
        assert_eq!(report.downloaded_bytes(), 4 * 32769);
        assert_eq!(
            report.supplying_peers(),
            &peers.into_iter().collect::<BTreeSet<_>>()
        );
        assert!(!report.cache_only());
        assert!(report.started_at() <= report.completed_at());
        assert!(report.completed_at() < report.deadline());
        assert!(report.transport().request_attempts >= 16);
        assert!(report.transport().received_response_bytes.unwrap() >= fixture.response_bytes());
        assert!(report.rejected_responses() > 0);
        let sent: u64 = providers
            .into_iter()
            .map(|provider| provider.finish().sent_response_bytes)
            .sum();
        assert_eq!(report.transport().received_response_bytes, Some(sent));
    }
}

fn missing_dependency_is_refused(environment: bool) {
    let fixture = Fixture::new();
    let missing = if environment {
        fixture.version.environment().files()[0].manifest
    } else {
        fixture
            .version
            .model()
            .closure()
            .files()
            .iter()
            .find(|file| file.role == CellFileRoleV1::Tokenizer)
            .unwrap()
            .manifest
    };
    let incomplete = fixture.cache("incomplete.sqlite");
    for member in fixture.version.manifests() {
        // All metadata is reachable, including the missing dependency's TCM1.
        fixture.copy_member(&incomplete, member, member.id() != missing);
    }
    let provider = Provider::start(&fixture.path("incomplete.sqlite"), persistent(64));
    let receiver = fixture.cache("receiver.sqlite");
    let failure = fixture
        .fetch(
            &receiver,
            &[provider.address],
            options(persistent(64)),
            None,
        )
        .unwrap_err();
    assert!(matches!(failure.error(), CellErrorV1::Unavailable));
    assert!(failure.transport().request_attempts > 4);
    assert!(failure.transport().received_response_bytes.unwrap() > 0);
    for member in fixture.version.manifests() {
        assert_eq!(
            receiver.manifest(member.id()).unwrap().as_ref(),
            Some(member)
        );
    }
    assert!(fixture
        .version
        .verify_cached(
            &receiver,
            &fixture.expected(),
            options(persistent(64)).limits.release
        )
        .is_err());
    provider.finish();
}

#[test]
fn reachable_model_cannot_substitute_for_missing_environment_dependency() {
    missing_dependency_is_refused(true);
}

#[test]
fn reachable_weights_cannot_substitute_for_missing_tokenizer_dependency() {
    missing_dependency_is_refused(false);
}

#[test]
fn model_and_environment_share_one_request_quota_and_failure_observation() {
    let fixture = Fixture::new();
    let provider = Provider::start(&fixture.path("cache.sqlite"), persistent(8));
    let receiver = fixture.cache("request-quota.sqlite");
    let mut limits = options(persistent(8));
    limits.limits.peer.max_connections = 1;
    let failure = fixture
        .fetch(&receiver, &[provider.address], limits, None)
        .unwrap_err();
    assert_eq!(failure.transport().connection_attempts, 1);
    assert_eq!(failure.transport().request_attempts, 8);
    assert!(failure.transport().received_response_bytes.unwrap() > 0);
    assert!(failure.transport().received_response_bytes.unwrap() < fixture.response_bytes());
    let served = provider.finish();
    assert_eq!(served.accepted_connections, 1);
    assert_eq!(served.completed_requests, 8);
    // Exactly sixteen requests suffice for all four TCM1s and twelve chunks;
    // the two contexts share the same one physical connection when permitted.
    let receiver = fixture.cache("exact-quota.sqlite");
    let provider = Provider::start(&fixture.path("cache.sqlite"), persistent(16));
    let mut limits = options(persistent(16));
    limits.limits.peer.max_connections = 1;
    limits.limits.peer.max_response_bytes = fixture.response_bytes();
    let report = fixture
        .fetch(&receiver, &[provider.address], limits, None)
        .unwrap();
    assert_eq!(report.transport().connection_attempts, 1);
    assert_eq!(report.transport().request_attempts, 16);
    assert_eq!(
        report.transport().received_response_bytes,
        Some(fixture.response_bytes())
    );
    assert_eq!(provider.finish().completed_requests, 16);
}

#[test]
fn model_and_environment_share_one_response_byte_quota() {
    let fixture = Fixture::new();
    let half_budget = [
        fixture.version.model().closure(),
        fixture.version.environment(),
    ]
    .into_iter()
    .map(|closure| {
        fixture
            .version
            .manifests()
            .iter()
            .filter(|manifest| closure.release().cells().contains(&manifest.id()))
            .map(member_response_bytes)
            .sum::<u64>()
    })
    .max()
    .unwrap();
    assert!(half_budget < fixture.response_bytes());
    for (run, profile) in [CellFetchTransportV2::OrderedV1, persistent(64)]
        .into_iter()
        .enumerate()
    {
        let receiver = fixture.cache(&format!("byte-quota-{run}.sqlite"));
        let provider = Provider::start(&fixture.path("cache.sqlite"), profile);
        let mut limits = options(profile);
        limits.limits.peer.max_response_bytes = half_budget;
        let failure = fixture
            .fetch(&receiver, &[provider.address], limits, None)
            .unwrap_err();
        assert!(matches!(
            failure.error(),
            CellErrorV1::ResponseByteBudgetExhausted {
                received_response_bytes,
                max_response_bytes
            } if *received_response_bytes == half_budget && *max_response_bytes == half_budget
        ));
        assert_eq!(
            failure.transport().received_response_bytes,
            Some(half_budget)
        );
        assert!(failure.transport().request_attempts > 4);
        provider.finish();
    }
}

#[test]
fn changed_owner_pins_and_contexts_refuse_before_network_or_cache_effects() {
    let fixture = Fixture::new();
    let receiver = fixture.cache("owner-refusal.sqlite");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peers = [listener.local_addr().unwrap()];
    for case in 0..6 {
        let mut model = fixture.model.clone();
        let mut environment = fixture.environment.clone();
        let mut commitment = fixture.version.commitment();
        match case {
            0 => commitment[0] ^= 1,
            1 => model.context.tokenizer[0] ^= 1,
            2 => environment.context.runtime[0] ^= 1,
            3 => environment.loader_profile[0] ^= 1,
            4 => model.selected_generation += 1,
            5 => environment.max_chunks = 5,
            _ => unreachable!(),
        }
        let expected = CellVersionLoaderContextV1 {
            commitment,
            model: &model,
            environment: &environment,
        };
        let failure = fetch_complete_version(
            &receiver,
            &fixture.version,
            &expected,
            &peers,
            options(CellFetchTransportV2::OrderedV1),
            None,
        )
        .unwrap_err();
        assert_no_network(failure.transport(), &listener);
        for member in fixture.version.manifests() {
            assert!(receiver.manifest(member.id()).unwrap().is_none());
        }
    }
}

#[test]
fn full_union_payload_chunk_and_member_limits_are_admitted_before_network() {
    let fixture = Fixture::new();
    let receiver = fixture.cache("aggregate-refusal.sqlite");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    for case in 0..3 {
        let mut limits = options(CellFetchTransportV2::OrderedV1);
        match case {
            0 => limits.limits.release.max_payload_bytes = 4 * 32769 - 1,
            1 => limits.limits.release.max_chunks = 11,
            2 => limits.limits.peer.max_cell_bytes = 32768,
            _ => unreachable!(),
        }
        let failure = fixture
            .fetch(&receiver, &[listener.local_addr().unwrap()], limits, None)
            .unwrap_err();
        assert_no_network(failure.transport(), &listener);
        for member in fixture.version.manifests() {
            assert!(receiver.manifest(member.id()).unwrap().is_none());
        }
    }
}

#[test]
fn warm_cache_is_explicitly_not_new_network_evidence_for_every_transport() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    for profile in PROFILES {
        let mut limits = options(profile);
        limits.limits.peer.max_connections = 1;
        limits.limits.peer.max_response_bytes = 0;
        let report = fixture
            .fetch(
                &fixture.source,
                &[listener.local_addr().unwrap()],
                limits,
                None,
            )
            .unwrap();
        assert!(report.cache_only());
        assert_no_network(report.transport(), &listener);
        assert_eq!(report.cached_chunks(), 12);
        assert_eq!(report.downloaded_chunks(), 0);
        assert_eq!(report.downloaded_bytes(), 0);
        assert!(report.supplying_peers().is_empty());
    }
}

#[test]
fn warm_cache_still_obeys_preexisting_cancellation_and_absolute_deadline() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let cancelled = AtomicBool::new(true);
    let failure = fixture
        .fetch(
            &fixture.source,
            &[listener.local_addr().unwrap()],
            options(CellFetchTransportV2::OrderedV1),
            Some(&cancelled),
        )
        .unwrap_err();
    assert!(matches!(failure.error(), CellErrorV1::Io(error)
        if error.kind() == io::ErrorKind::Interrupted && error.to_string().contains("CELL_OPERATION_CANCELLED")));
    assert_no_network(failure.transport(), &listener);
    let mut expired = options(CellFetchTransportV2::OrderedV1);
    expired.limits.release.deadline = Instant::now() - Duration::from_secs(1);
    let failure = fixture
        .fetch(
            &fixture.source,
            &[listener.local_addr().unwrap()],
            expired,
            None,
        )
        .unwrap_err();
    assert_no_network(failure.transport(), &listener);
}

fn accept_before(listener: &TcpListener, deadline: Instant) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                return stream;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("version test accept: {error}"),
        }
    }
}

fn read_manifest_query(stream: &mut TcpStream) {
    let mut query = [0; 37];
    stream.read_exact(&mut query).unwrap();
    assert_eq!(&query[..4], b"TCQ1");
    assert_eq!(query[4], 1);
}

#[test]
fn cancelled_real_tcp_attempt_keeps_counters_and_does_not_retry() {
    let fixture = Fixture::new();
    let receiver = fixture.cache("cancelled.sqlite");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let cancelled = AtomicBool::new(false);
    let failure = thread::scope(|scope| {
        let provider = scope.spawn(|| {
            let mut stream = accept_before(&listener, Instant::now() + Duration::from_secs(3));
            read_manifest_query(&mut stream);
            stream.write_all(b"TCS1").unwrap();
            cancelled.store(true, Ordering::Release);
            let _ = stream.read(&mut [0; 1]);
        });
        let result = fixture.fetch(
            &receiver,
            &[peer],
            options(CellFetchTransportV2::OrderedV1),
            Some(&cancelled),
        );
        provider.join().unwrap();
        result.unwrap_err()
    });
    assert!(matches!(failure.error(), CellErrorV1::Io(error)
        if error.kind() == io::ErrorKind::Interrupted && error.to_string().contains("CELL_OPERATION_CANCELLED")));
    assert_eq!(failure.transport().connection_attempts, 1);
    assert_eq!(failure.transport().request_attempts, 1);
    // Cancellation may be observed immediately before or after receiving the
    // partial header; only actual reads are charged, never the provider write.
    assert!(failure.transport().received_response_bytes.unwrap() <= 4);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn original_absolute_deadline_expires_during_a_real_tcp_response() {
    let fixture = Fixture::new();
    let receiver = fixture.cache("deadline.sqlite");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let mut limits = options(CellFetchTransportV2::OrderedV1);
    limits.limits.release.deadline = Instant::now() + Duration::from_millis(900);
    let original_deadline = limits.limits.release.deadline;
    let failure = thread::scope(|scope| {
        let provider = scope.spawn(|| {
            let mut stream = accept_before(&listener, Instant::now() + Duration::from_secs(3));
            read_manifest_query(&mut stream);
            stream.write_all(b"TCS1").unwrap();
            // Keep the frame incomplete until the original client deadline
            // closes the connection; no new timeout is granted by a file edge.
            let _ = stream.read(&mut [0; 1]);
        });
        let result = fixture.fetch(&receiver, &[peer], limits, None);
        provider.join().unwrap();
        result.unwrap_err()
    });
    assert!(Instant::now() >= original_deadline);
    assert_eq!(failure.transport().connection_attempts, 1);
    assert_eq!(failure.transport().request_attempts, 1);
    assert_eq!(failure.transport().received_response_bytes, Some(4));
}

#[test]
fn failed_partial_response_retry_spends_original_attempt_and_byte_budgets() {
    let fixture = Fixture::new();
    let receiver = fixture.cache("failed-retry.sqlite");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let mut limits = options(CellFetchTransportV2::OrderedV1);
    limits.limits.peer.max_connections = 2;
    limits.limits.peer.max_response_bytes = 8;
    let failure = thread::scope(|scope| {
        let provider = scope.spawn(|| {
            for _ in 0..2 {
                let mut stream = accept_before(&listener, Instant::now() + Duration::from_secs(3));
                read_manifest_query(&mut stream);
                stream.write_all(b"TCS1").unwrap();
                // Closing this partial frame permits at most the existing one
                // transport retry, charged to the same session reservation.
            }
        });
        let result = fixture.fetch(&receiver, &[peer], limits, None);
        provider.join().unwrap();
        result.unwrap_err()
    });
    assert_eq!(failure.transport().connection_attempts, 2);
    assert_eq!(failure.transport().request_attempts, 2);
    assert_eq!(failure.transport().received_response_bytes, Some(8));
    assert!(matches!(
        failure.error(),
        CellErrorV1::ResponseByteBudgetExhausted {
            received_response_bytes: 8,
            max_response_bytes: 8,
        }
    ));
    for member in fixture.version.manifests() {
        assert!(receiver.manifest(member.id()).unwrap().is_none());
    }
}
