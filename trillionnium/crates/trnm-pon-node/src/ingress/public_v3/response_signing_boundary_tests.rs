//! Real TCP/signature and original owner boundaries for deferred response CPU.
//! Channel gates expose ordering; they are not attack-cost or Host qualification.
use super::*;
use std::net::Shutdown;
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn classical_identity(key: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([key; 32])).unwrap()
}

fn pq_identity(key: u8) -> PqPublicIdentity {
    let seed = Zeroizing::new([key; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    PqPublicIdentity::from_owned_seed(seed, ml_dsa_65_key_id_from_spki(&spki).unwrap()).unwrap()
}

fn signing_identity(pq: bool, key: u8) -> SigningIdentity {
    if pq {
        SigningIdentity::Pq(Box::new(pq_identity(key)))
    } else {
        SigningIdentity::Classical(Box::new(classical_identity(key)))
    }
}

fn fresh_node() -> (tempfile::TempDir, Node) {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(crate::ingress::now().unwrap() - 100)).unwrap();
    let node = Node::open(directory.path(), settings, 1).unwrap();
    (directory, node)
}

fn native_submit(node: &Node) -> (Request, Hash) {
    let packet = node
        .make(
            node.read_active().unwrap().0,
            super::tests::accounting_transactions(node.settings(), 1, 1),
            crate::development_public(0).unwrap(),
            crate::ingress::now().unwrap() - 50,
            4096,
        )
        .unwrap();
    (
        Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        },
        packet.id().unwrap(),
    )
}

struct Stop(Arc<AtomicBool>);
impl Drop for Stop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Unwinding an assertion also releases the real worker before its scope joins.
struct Release(Option<mpsc::Sender<()>>);
impl Release {
    fn now(mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

fn received<T>(receiver: &mpsc::Receiver<T>) -> T {
    receiver
        .recv_timeout(Duration::from_millis(WORK_MS))
        .expect("actual worker did not reach the bounded channel checkpoint")
}

fn observed<T>(mut sample: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_millis(WORK_MS);
    loop {
        if let Some(value) = sample() {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "actual lifecycle checkpoint absent"
        );
        // The observed predicate determines progress; no fixed sleep orders it.
        thread::yield_now();
    }
}

struct Fixture {
    address: SocketAddr,
    settings: Settings,
    policy: PublicPolicy,
    key: String,
    spki: Option<Vec<u8>>,
    owner: Arc<Mutex<Node>>,
    metrics: Arc<Mutex<PublicMetrics>>,
    observer: PublicRequestObserver,
    domain: ServiceMutationCpuDomain,
    intake: Arc<ListenerIntake>,
}

#[derive(Debug)]
struct AuthenticationObservation {
    in_flight: usize,
    pending: usize,
    known: u64,
    unknown: u64,
    credit: i128,
    unavailable: bool,
}

fn with_server(node: Node, pq: bool, test: impl FnOnce(&Fixture)) -> PublicMetrics {
    let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
    let server = if pq {
        PublicServer::new_pq_history(pq_identity(71), policy).unwrap()
    } else {
        PublicServer::new(classical_identity(71), policy).unwrap()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = Fixture {
        address: listener.local_addr().unwrap(),
        settings: node.settings().clone(),
        policy,
        key: server.identity.public_key().to_owned(),
        spki: match &server.identity {
            SigningIdentity::Classical(_) => None,
            SigningIdentity::Pq(key) => Some(key.public_spki().to_vec()),
        },
        owner: super::tests::shared(node),
        metrics: Arc::new(Mutex::new(PublicMetrics::default())),
        observer: PublicRequestObserver::new(16).unwrap(),
        domain: server.mutation_cpu_domain(),
        intake: server.listener_intake().unwrap(),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let (owner, metrics, observer, stopping) = (
        fixture.owner.clone(),
        fixture.metrics.clone(),
        fixture.observer.clone(),
        stop.clone(),
    );
    thread::scope(|scope| {
        let service = scope.spawn(move || {
            serve_public_protected_v3_with_request_observer(
                listener,
                owner,
                Duration::from_millis(OVERALL_MS),
                stopping,
                server,
                metrics,
                observer,
            )
        });
        let _stop = Stop(stop.clone());
        // This genuine reply synchronizes startup before any Node-lock gate.
        assert!(fixture.call(&Request::Head).unwrap().ok);
        fixture.complete_record(0);
        test(&fixture);
        stop.store(true, Ordering::Release);
        service.join().unwrap().unwrap()
    })
}

impl Fixture {
    fn is_pq(&self) -> bool {
        self.spki.is_some()
    }

    fn pin(&self) -> ServerPin<'_> {
        match &self.spki {
            None => ServerPin::Classical(&self.key),
            Some(spki) => ServerPin::Pq {
                key_id: self.key.clone(),
                verifier: Box::new(
                    PqNativeVerifier::from_pinned_spki(spki, digest(&self.key).unwrap()).unwrap(),
                ),
            },
        }
    }

    fn call(&self, request: &Request) -> Result<PublicReply> {
        match &self.spki {
            None => call_public_protected_v3(
                self.address,
                request,
                &self.settings,
                &self.key,
                &classical_identity(72),
                self.policy,
            ),
            Some(spki) => {
                call_public_history_pq_v4(
                    self.address,
                    request,
                    &self.settings,
                    spki,
                    digest(&self.key).unwrap(),
                    &pq_identity(72),
                    self.policy,
                    None,
                )
                .0
            }
        }
    }

    fn authentication(&self) -> AuthenticationObservation {
        if self.is_pq() {
            let usage = self.domain.observe_pq_authentication_cpu().unwrap();
            AuthenticationObservation {
                in_flight: usage.in_flight,
                pending: usage.pending_response_signatures,
                known: usage.known_intervals,
                unknown: usage.unknown_intervals,
                credit: usage.stored_credit_ns,
                unavailable: usage.unavailable,
            }
        } else {
            let usage = self.domain.observe_classical_authentication_cpu().unwrap();
            AuthenticationObservation {
                in_flight: usage.in_flight,
                pending: usage.pending_response_signatures,
                known: usage.known_intervals,
                unknown: usage.unknown_intervals,
                credit: usage.stored_credit_ns,
                unavailable: usage.unavailable,
            }
        }
    }

    fn pause_response(&self) -> (mpsc::Receiver<()>, Release) {
        let (entered, release) = if self.is_pq() {
            self.intake
                .pq_authentication
                .pause_next_response_after_signing_for_test()
        } else {
            self.intake
                .classical_authentication
                .pause_next_response_after_signing_for_test()
        };
        (entered, Release(Some(release)))
    }

    fn fail_response_finish(&self) {
        if self.is_pq() {
            self.intake.pq_authentication.fail_next_finish_for_test();
        } else {
            self.intake
                .classical_authentication
                .fail_next_finish_for_test();
        }
    }

    fn other_authentication(
        &self,
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    ) -> Result<()> {
        let signer = signing_identity(self.is_pq(), 73);
        let operation = || {
            // Real signing precedes the test-only wait in this original interval.
            signer.sign(&[7; 32])?;
            entered.send(()).map_err(|_| "TEST_RESPONSE_FINISH_GATE")?;
            release
                .recv_timeout(Duration::from_millis(WORK_MS))
                .map_err(|_| "TEST_RESPONSE_FINISH_GATE")?;
            Ok(())
        };
        if self.is_pq() {
            self.intake.pq_authentication.perform(32, operation)
        } else {
            self.intake.classical_authentication.perform(32, operation)
        }
    }

    fn assert_authentication_full(&self) {
        let called = AtomicBool::new(false);
        let operation = || {
            called.store(true, Ordering::Release);
            Ok(())
        };
        let result = if self.is_pq() {
            self.intake.pq_authentication.perform(32, operation)
        } else {
            self.intake.classical_authentication.perform(32, operation)
        };
        assert!(result
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuBudget));
        assert!(!called.load(Ordering::Acquire));
        assert_eq!(self.authentication().in_flight, MUTATION_CPU_WORKERS);
    }

    fn record(&self, index: usize) -> PublicRequestObservation {
        self.observer.snapshot().records[index].clone()
    }

    fn complete_record(&self, index: usize) -> PublicRequestObservation {
        observed(|| {
            (self.observer.lifecycle_closed_for_test(index) == Some((true, true))).then_some(())
        });
        let record = self.record(index);
        assert!(record.complete && !record.observation_failed);
        record
    }

    fn begin_request(&self, request: &Request) -> PendingResponse {
        let pq = self.is_pq();
        let key = signing_identity(pq, 72);
        let caller = match &key {
            SigningIdentity::Classical(key) => Caller::Classical(key),
            SigningIdentity::Pq(key) => Caller::Pq(key),
        };
        let raw = serde_json::to_vec(request).unwrap();
        let hello = Hello {
            op: request_op(request).unwrap(),
            len: raw.len(),
            caller: digest(caller.public_key()).unwrap(),
            digest: hash(b"public-request-body-v3", &[&raw]),
            client_nonce: [19; 32],
        };
        let index = self.observer.snapshot().records.len();
        let mut socket = TcpStream::connect(self.address).unwrap();
        socket.set_nodelay(true).unwrap();
        let solution_deadline = Instant::now() + Duration::from_millis(PREFIX_MS);
        let deadline = Instant::now() + Duration::from_millis(OVERALL_MS);
        client_write(&mut socket, &hello.encode_for(pq), solution_deadline).unwrap();
        let bytes = client_frame(
            &mut socket,
            pq_identity::challenge_maximum(pq),
            solution_deadline,
        )
        .unwrap();
        let cookie: Cookie = serde_json::from_slice(&bytes).unwrap();
        validate_challenge_context_authenticated(
            &bytes,
            &cookie,
            &hello,
            &self.settings,
            &self.pin(),
            self.policy,
            if pq {
                self.policy.pq_history_id()
            } else {
                self.policy.id()
            },
        )
        .unwrap();
        let id = cookie.id().unwrap();
        let nonce = (0..1_048_576u64)
            .find(|n| winner(id, *n, cookie.bits))
            .expect("original bounded ticket search");
        let mut solution = pq_identity::solution_magic(pq).to_vec();
        solution.extend(id);
        solution.extend(nonce.to_le_bytes());
        caller.append_spki(&mut solution);
        solution.extend(
            hex::decode(
                caller
                    .sign(&pq_identity::caller_message(&cookie, nonce, pq).unwrap())
                    .unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(solution.len(), pq_identity::solution_bytes(pq));
        client_write(&mut socket, &solution, solution_deadline).unwrap();
        let ready: Value =
            serde_json::from_slice(&client_frame(&mut socket, 256, solution_deadline).unwrap())
                .unwrap();
        assert_eq!(
            ready["schema"],
            pq_identity::schema(pq, "public-body-ready-v3", "public-body-ready-pq-v4")
        );
        assert_eq!(ready["cookie_digest"], hex::encode(id));
        client_write(
            &mut socket,
            &raw,
            deadline.min(Instant::now() + Duration::from_millis(BODY_MS)),
        )
        .unwrap();
        PendingResponse {
            socket,
            cookie,
            index,
            deadline,
        }
    }
}

struct PendingResponse {
    socket: TcpStream,
    cookie: Cookie,
    index: usize,
    deadline: Instant,
}
impl PendingResponse {
    fn read(mut self, fixture: &Fixture) -> Result<Response> {
        let bytes = client_frame(
            &mut self.socket,
            pq_identity::response_maximum_for(self.cookie.op, fixture.is_pq()),
            self.deadline
                .min(Instant::now() + Duration::from_millis(WORK_MS + OUTPUT_MS)),
        )?;
        let response: Response = serde_json::from_slice(&bytes)?;
        assert_eq!(serde_json::to_vec(&response).unwrap(), bytes);
        assert_eq!(
            response.cookie_digest,
            hex::encode(self.cookie.id().unwrap())
        );
        assert_eq!(response.request_digest, self.cookie.body_digest);
        fixture
            .pin()
            .verify(&response.message()?, &response.signature)?;
        Ok(response)
    }
}

#[test]
fn submit_ack_keeps_its_authentication_slot_while_a_real_head_competes() {
    let (_directory, node) = fresh_node();
    let before = node.read_active().unwrap();
    let (request, packet_id) = native_submit(&node);
    let metrics = with_server(node, false, |fixture| {
        let owner = fixture.owner.lock().unwrap();
        let pending = fixture.begin_request(&request);
        observed(|| (fixture.authentication().pending == 1).then_some(()));
        assert_eq!(fixture.authentication().pending, 1);
        thread::scope(|scope| {
            let (started, entered) = mpsc::channel();
            let (release, until_release) = mpsc::channel();
            let other = scope.spawn(move || fixture.other_authentication(started, until_release));
            let release = Release(Some(release));
            received(&entered);
            fixture.assert_authentication_full();
            let before_challenge = fixture.metrics.lock().unwrap().pending_challenge_entered;
            let (done, response) = mpsc::channel();
            let head = scope.spawn(move || done.send(fixture.call(&Request::Head)).unwrap());
            observed(|| {
                (fixture.metrics.lock().unwrap().pending_challenge_entered > before_challenge)
                    .then_some(())
            });
            // The competing real Head and another active crypto interval cannot
            // seize the Submit's promised response slot after its native commit.
            drop(owner);
            assert!(pending.read(fixture).unwrap().ok);
            assert!(received(&response).unwrap().ok);
            let active = fixture.owner.lock().unwrap().read_active().unwrap();
            assert_eq!(active.0, packet_id);
            assert_ne!(active, before);
            // Both real replies must arrive BEFORE releasing the other signer.
            assert_eq!(fixture.authentication().in_flight, 1);
            release.now();
            other.join().unwrap().unwrap();
            head.join().unwrap();
        });
    });
    assert_eq!(metrics.completed_submit, 1);
}

#[test]
fn classical_and_pq_head_responses_use_their_reserved_slots() {
    for pq in [false, true] {
        let (_directory, node) = fresh_node();
        let before = node.read_active().unwrap();
        with_server(node, pq, |fixture| {
            let owner = fixture.owner.lock().unwrap();
            let pending = fixture.begin_request(&Request::Head);
            observed(|| (fixture.authentication().pending == 1).then_some(()));
            assert_eq!(fixture.authentication().pending, 1);
            thread::scope(|scope| {
                let (started, entered) = mpsc::channel();
                let (release, until_release) = mpsc::channel();
                let other =
                    scope.spawn(move || fixture.other_authentication(started, until_release));
                let release = Release(Some(release));
                received(&entered);
                fixture.assert_authentication_full();
                drop(owner);
                assert!(pending.read(fixture).unwrap().ok);
                assert_eq!(fixture.authentication().in_flight, 1);
                assert_eq!(fixture.owner.lock().unwrap().read_active().unwrap(), before);
                release.now();
                other.join().unwrap().unwrap();
            });
        });
    }
}

#[test]
fn tcp_cancellation_keeps_real_response_signing_interval_until_worker_returns() {
    for pq in [false, true] {
        for unknown_finish in [false, true] {
            let (_directory, node) = fresh_node();
            with_server(node, pq, |fixture| {
                let (entered, release) = fixture.pause_response();
                let pending = fixture.begin_request(&Request::Head);
                received(&entered);
                let held = fixture.authentication();
                assert_eq!(held.in_flight, 1);
                assert_eq!(held.pending, 0);
                assert!(!held.unavailable);
                // The real signature has returned, but its original worker CPU
                // interval has not settled. This gate does not pretend that the
                // signing algorithm is still running or measure attack cost.
                pending.socket.shutdown(Shutdown::Both).unwrap();
                observed(|| {
                    fixture
                        .observer
                        .lifecycle_closed_for_test(pending.index)
                        .filter(|(connection_closed, _)| *connection_closed)
                        .map(|_| ())
                });
                let disconnected = fixture.record(pending.index);
                assert!(!disconnected.observation_failed);
                assert_eq!(disconnected.terminal_phase, Some("work"));
                assert_eq!(
                    disconnected.terminal_error_code,
                    Some(crate::ErrorCode::PublicEof.as_str())
                );
                let cancelled = fixture.authentication();
                assert_eq!(cancelled.in_flight, held.in_flight);
                assert_eq!(cancelled.known, held.known);
                assert_eq!(cancelled.unknown, held.unknown);
                assert_eq!(cancelled.credit, held.credit);
                assert!(!fixture.record(pending.index).task_closed);
                if unknown_finish {
                    fixture.fail_response_finish();
                }
                release.now();
                let record = fixture.complete_record(pending.index);
                assert_eq!(record.dispatch_accepted, Some(true));
                assert!(!record.response_frame_complete);
                let settled = fixture.authentication();
                assert_eq!(settled.in_flight, 0);
                assert_eq!(settled.pending, 0);
                if unknown_finish {
                    assert!(settled.unavailable);
                    assert_eq!(settled.unknown, held.unknown + 1);
                    assert_eq!(settled.known, held.known);
                    assert!(settled.credit <= held.credit);
                } else {
                    assert!(!settled.unavailable);
                    assert_eq!(settled.known, held.known + 1);
                    assert_eq!(settled.unknown, held.unknown);
                }
            });
        }
    }
}

#[test]
fn unknown_response_cpu_preserves_committed_native_outcome_without_refund() {
    let (_directory, node) = fresh_node();
    let before = node.read_active().unwrap();
    let (request, packet_id) = native_submit(&node);
    let metrics = with_server(node, false, |fixture| {
        let (entered, release) = fixture.pause_response();
        let pending = fixture.begin_request(&request);
        let index = pending.index;
        received(&entered);
        let held = fixture.authentication();
        let committed = fixture.owner.lock().unwrap().read_active().unwrap();
        assert_eq!(committed.0, packet_id);
        assert_ne!(committed, before);
        fixture.fail_response_finish();
        release.now();
        assert!(pending.read(fixture).is_err());
        let record = fixture.complete_record(index);
        assert_eq!(record.dispatch_accepted, Some(true));
        assert_eq!(record.full_work_accepted, Some(true));
        assert_eq!(record.dispatch_error_code, None);
        assert_eq!(record.terminal_phase, Some("serialization"));
        assert_eq!(
            record.terminal_error_code,
            Some(crate::ErrorCode::PublicMutationCpuUnavailable.as_str())
        );
        assert!(!record.response_frame_complete);
        assert_eq!(
            fixture.owner.lock().unwrap().read_active().unwrap(),
            committed
        );
        let failed = fixture.authentication();
        assert_eq!(failed.in_flight, 0);
        assert_eq!(failed.unknown, held.unknown + 1);
        assert!(failed.unavailable);
        assert!(failed.credit <= held.credit);
        let called = AtomicBool::new(false);
        assert!(fixture
            .intake
            .classical_authentication
            .perform(32, || {
                called.store(true, Ordering::Release);
                Ok(())
            })
            .unwrap_err()
            .is(crate::ErrorCode::PublicMutationCpuUnavailable));
        assert!(!called.load(Ordering::Acquire));
    });
    assert_eq!(metrics.completed_submit, 1);
}

fn pq_response_message() -> Vec<u8> {
    let mut message = b"TRNM/PoN/PaidHistory/Response/PQ/v4\0".to_vec();
    message.extend([17; 48]);
    message
}

fn pq_server(domain: &ServiceMutationCpuDomain) -> PublicServer {
    PublicServer::with_continuous_pq_history(
        pq_identity(71),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        domain,
    )
    .unwrap()
}

#[test]
fn last_history_owner_cannot_clear_pq_pending_or_unknown_response_principal() {
    for unknown_finish in [false, true] {
        let (directory, mut node) = fresh_node();
        let settings = node.settings().clone();
        let state = node.read_active().unwrap();
        let domain = ServiceMutationCpuDomain::standalone();
        node.bind_public_service_cpu_domain(&domain).unwrap();
        assert!(node.begin_ordinary_public_service_epoch().unwrap());
        assert!(node.begin_remote_history_cpu_epoch().unwrap());
        let server = pq_server(&domain);
        let intake = server.listener_intake().unwrap();
        let mut reservation = Some(server.reserve_response_signing(&intake).unwrap());
        if unknown_finish {
            intake.pq_authentication.fail_next_finish_for_test();
            assert!(reservation
                .take()
                .unwrap()
                .sign(&server, &pq_response_message())
                .unwrap_err()
                .is(crate::ErrorCode::PublicMutationCpuUnavailable));
        }
        let usage = domain.observe_pq_authentication_cpu().unwrap();
        assert_eq!(usage.reserved_cpu_ns, MUTATION_CPU_START_RESERVE_NS);
        assert_eq!(
            usage.pending_response_signatures,
            usize::from(!unknown_finish)
        );
        assert_eq!(usage.unknown_intervals, u64::from(unknown_finish));
        assert!(!domain.public_epoch_is_settled().unwrap());
        node.finish_ordinary_public_service_epoch(false).unwrap();
        node.finish_remote_history_cpu_epoch(&domain).unwrap();
        drop(reservation);
        assert_eq!(node.read_active().unwrap(), state);
        assert!(node
            .begin_ordinary_public_service_epoch()
            .unwrap_err()
            .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
        drop(node);
        let mut reopened = Node::open(directory.path(), settings, 1).unwrap();
        assert!(reopened
            .bind_public_service_cpu_domain(&ServiceMutationCpuDomain::standalone())
            .unwrap_err()
            .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
        assert_eq!(reopened.read_active().unwrap(), state);
    }
}

#[test]
fn continuous_pq_response_pending_is_busy_and_unknown_fences_clean_close() {
    use crate::operator_continuous_history::{Anchor, Journal};
    use crate::operator_task_policy::PolicyError;

    for unknown_finish in [false, true] {
        // This is the existing Journal/owner guard fixture. It grants neither
        // qualified continuous Work nor an alternate production startup path.
        let (_native, directory, node) = Node::continuous_authentication_guard_fixture();
        let state = node.read_active().unwrap();
        let head = node.continuous_journal_head().unwrap();
        let anchor: Anchor = serde_json::from_value(head.clone()).unwrap();
        let domain = node.continuous_cpu_domain().unwrap();
        let server = pq_server(&domain);
        let intake = server.listener_intake().unwrap();
        let reservation = server.reserve_response_signing(&intake).unwrap();
        assert!(!domain.public_epoch_is_settled().unwrap());
        assert_eq!(
            node.close_continuous_checkpoint().unwrap_err().to_string(),
            "OWNER_CONTINUOUS_SCOPE_BUSY"
        );
        assert_eq!(node.continuous_journal_head().unwrap(), head);
        assert_eq!(node.read_active().unwrap(), state);
        assert!(!directory.path().join("unavailable.json").exists());
        if unknown_finish {
            intake.pq_authentication.fail_next_finish_for_test();
            assert!(reservation
                .sign(&server, &pq_response_message())
                .unwrap_err()
                .is(crate::ErrorCode::PublicMutationCpuUnavailable));
            assert!(node
                .close_continuous_checkpoint()
                .unwrap_err()
                .is(crate::ErrorCode::PublicMutationCpuUnavailable));
            assert_eq!(node.continuous_journal_head().unwrap(), head);
            assert_eq!(node.read_active().unwrap(), state);
            let fault: Value = serde_json::from_slice(
                &std::fs::read(directory.path().join("unavailable.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(fault["schema"], "restricted-continuous-accounting-fault-v2");
            assert_eq!(fault["label"], "CPU_OR_JOURNAL_UNKNOWN");
            drop(node);
            assert_eq!(
                Journal::open(
                    directory.path(),
                    rustix::process::geteuid().as_raw(),
                    &crate::operator_continuous_test_support::identity(),
                    &anchor,
                )
                .err()
                .unwrap(),
                PolicyError::CpuUnknown
            );
        } else {
            let signature = reservation.sign(&server, &pq_response_message()).unwrap();
            let signer = pq_identity(71);
            PqNativeVerifier::from_pinned_spki(
                signer.public_spki(),
                digest(signer.public_key()).unwrap(),
            )
            .unwrap()
            .verify_exact_message(&pq_response_message(), &hex::decode(signature).unwrap())
            .unwrap();
            assert!(domain.public_epoch_is_settled().unwrap());
            let closed = node.close_continuous_checkpoint().unwrap();
            assert_eq!(
                closed["schema"],
                "restricted-continuous-clean-checkpoint-v2"
            );
            assert_ne!(node.continuous_journal_head().unwrap(), head);
            assert_eq!(node.read_active().unwrap(), state);
            assert!(!directory.path().join("unavailable.json").exists());
        }
    }
}
