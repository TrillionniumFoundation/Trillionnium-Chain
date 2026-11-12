//! Real signed TCP requests against the original shared output pool.
//! Filled-pool fixtures test ownership; they are not a traffic goodput campaign.
use super::*;
use trnm_crypto_primitives::pq_auth::PqNativeSigningKey;
use trnm_protocol::pq_frame::ml_dsa_65_key_id_from_spki;
use zeroize::Zeroizing;

fn classical(seed: u8) -> DevelopmentIdentity {
    DevelopmentIdentity::from_secret_hex(&hex::encode([seed; 32])).unwrap()
}

fn pq_identity(seed: u8) -> PqPublicIdentity {
    let seed = Zeroizing::new([seed; 32]);
    let spki = PqNativeSigningKey::public_spki_from_seed(&seed);
    PqPublicIdentity::from_owned_seed(seed, ml_dsa_65_key_id_from_spki(&spki).unwrap()).unwrap()
}

enum Client {
    Classical {
        caller: Box<DevelopmentIdentity>,
        server: String,
    },
    Pq {
        caller: Box<PqPublicIdentity>,
        spki: Vec<u8>,
        id: Hash,
    },
}

struct Running {
    _directory: tempfile::TempDir,
    settings: Settings,
    owner: Arc<Mutex<Node>>,
    intake: Arc<ListenerIntake>,
    address: SocketAddr,
    client: Client,
    policy: PublicPolicy,
    stop: Arc<AtomicBool>,
    metrics: Arc<Mutex<PublicMetrics>>,
    worker: Option<thread::JoinHandle<Result<PublicMetrics>>>,
}

impl Running {
    fn new(pq: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(super::super::now().unwrap() - 100)).unwrap();
        let owner =
            super::tests::shared(Node::open(directory.path(), settings.clone(), 1).unwrap());
        let policy = PublicPolicy::new(8, Duration::from_secs(2)).unwrap();
        let (server, client) = if pq {
            let identity = pq_identity(61);
            let client = Client::Pq {
                caller: Box::new(pq_identity(62)),
                spki: identity.public_spki().to_vec(),
                id: digest(identity.public_key()).unwrap(),
            };
            (
                PublicServer::new_pq_history(identity, policy).unwrap(),
                client,
            )
        } else {
            let identity = classical(61);
            let client = Client::Classical {
                caller: Box::new(classical(62)),
                server: identity.public_key().to_owned(),
            };
            (PublicServer::new(identity, policy).unwrap(), client)
        };
        let intake = server.listener_intake().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Mutex::new(PublicMetrics::default()));
        let worker = {
            let owner = owner.clone();
            let stop = stop.clone();
            let metrics = metrics.clone();
            thread::spawn(move || {
                serve_public_protected_v3_with_metrics(
                    listener,
                    owner,
                    Duration::from_secs(30),
                    stop,
                    server,
                    metrics,
                )
            })
        };
        Self {
            _directory: directory,
            settings,
            owner,
            intake,
            address,
            client,
            policy,
            stop,
            metrics,
            worker: Some(worker),
        }
    }

    fn call(&self, request: &Request) -> Result<PublicReply> {
        let deadline = Some(Instant::now() + Duration::from_secs(15));
        match &self.client {
            Client::Classical { caller, server } => {
                call_public_protected_v3_with_deadline(
                    self.address,
                    request,
                    &self.settings,
                    server,
                    caller,
                    self.policy,
                    deadline,
                )
                .0
            }
            Client::Pq { caller, spki, id } => {
                call_public_history_pq_v4(
                    self.address,
                    request,
                    &self.settings,
                    spki,
                    *id,
                    caller,
                    self.policy,
                    deadline,
                )
                .0
            }
        }
    }

    fn finish(&mut self) -> PublicMetrics {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap().unwrap()
    }

    fn wait_for_output(&self, admission_refusals: u64, delivered: u64, reserved: usize) {
        // Socket EOF/frame observation can precede the reactor's bookkeeping
        // by a scheduling turn. Synchronize only on this request's completion;
        // this does not extend any server request, work or output deadline.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let observed = self.metrics.lock().unwrap();
            let complete = observed.output_admission_refusals == admission_refusals
                && observed.delivered_response_frames == delivered;
            drop(observed);
            if complete && *self.intake.output_pool.lock().unwrap() == reserved {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "original output owner did not settle"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn full_output_pool_closes_without_signed_response_and_recovers_after_release() {
    for pq in [false, true] {
        let mut run = Running::new(pq);
        let before = run.owner.lock().unwrap().read_active().unwrap();
        let full = BufferPermit::acquire(
            run.intake.output_pool.clone(),
            MAX_OUTPUT_BYTES,
            MAX_OUTPUT_BYTES,
        )
        .unwrap();
        // Real challenge, ticket and caller authentication still happen. With
        // no output reservation, no response signature or bytes may be made.
        let error = run
            .call(&Request::Head)
            .expect_err("unreserved output must close");
        assert!(error.is(crate::ErrorCode::FrameEof), "{error}");
        run.wait_for_output(1, 0, MAX_OUTPUT_BYTES);
        let observed = run.metrics.lock().unwrap().clone();
        assert_eq!(observed.tasks_dequeued, 1);
        assert_eq!(observed.output_admission_refusals, 1);
        assert_eq!(observed.output_refusal_reservations, 0);
        assert_eq!(observed.output_serialization_failures, 0);
        assert_eq!(observed.delivered_response_frames, 0);
        assert_eq!(observed.completed_read, 0);
        assert_eq!(observed.mutation_cpu_reservations, 0);
        assert_eq!(observed.peak_output_reserved_bytes, MAX_OUTPUT_BYTES);
        if pq {
            // Only cookie signing and caller verification, not response signing.
            assert_eq!(run.intake.pq_authentication.usage().unwrap().attempts, 2);
        }
        assert_eq!(*run.intake.output_pool.lock().unwrap(), MAX_OUTPUT_BYTES);
        assert_eq!(run.owner.lock().unwrap().read_active().unwrap(), before);
        drop(full);
        let reply = run.call(&Request::Head).unwrap();
        assert!(reply.ok, "{}", reply.value);
        let observed = run.finish();
        assert_eq!(observed.completed_read, 1);
        assert_eq!(observed.delivered_response_frames, 1);
        assert_eq!(observed.output_admission_refusals, 1);
        assert_eq!(observed.output_reserved_bytes_after_shutdown, 0);
        assert_eq!(observed.paid_body_reserved_bytes_after_shutdown, 0);
        assert_eq!(observed.read_grants_after_shutdown, 0);
        assert_eq!(run.owner.lock().unwrap().read_active().unwrap(), before);
    }
}

#[test]
fn refusal_borrows_only_bounded_original_headroom_and_preserves_control_service() {
    for pq in [false, true] {
        let mut run = Running::new(pq);
        let ordinary = MAX_OUTPUT_BYTES - CONTROL_OUTPUT_RESERVE;
        let bulk =
            BufferPermit::acquire(run.intake.output_pool.clone(), ordinary, ordinary).unwrap();
        let history = Request::History {
            tip: hex::encode(run.settings.genesis()),
            after: hex::encode(run.settings.genesis()),
        };
        let reply = run.call(&history).unwrap();
        assert!(!reply.ok);
        assert_eq!(reply.value["error"], "PUBLIC_BUFFER_CAPACITY");
        run.wait_for_output(0, 1, ordinary);
        if pq {
            assert_eq!(run.intake.pq_authentication.usage().unwrap().attempts, 3);
        }
        let observed = run.metrics.lock().unwrap().clone();
        let frame = if pq {
            PQ_REFUSAL_FRAME
        } else {
            CLASSICAL_REFUSAL_FRAME
        };
        assert_eq!(observed.output_refusal_reservations, 1);
        assert_eq!(observed.peak_output_reserved_bytes, ordinary + 4 * frame);
        assert!(observed.peak_output_reserved_bytes <= ordinary + REFUSAL_OUTPUT_HEADROOM);
        assert_eq!(
            observed.completed_read, 0,
            "refusal must not dispatch History"
        );
        assert_eq!(observed.output_admission_refusals, 0);
        // Occupy the complete allowed fallback slice too. A further History
        // response must close, while Head still uses the reserved control space.
        let fallback = BufferPermit::acquire(
            run.intake.output_pool.clone(),
            REFUSAL_OUTPUT_HEADROOM,
            ordinary + REFUSAL_OUTPUT_HEADROOM,
        )
        .unwrap();
        let error = run
            .call(&history)
            .expect_err("fallback headroom is bounded");
        assert!(error.is(crate::ErrorCode::FrameEof), "{error}");
        run.wait_for_output(1, 1, ordinary + REFUSAL_OUTPUT_HEADROOM);
        if pq {
            assert_eq!(run.intake.pq_authentication.usage().unwrap().attempts, 5);
        }
        let head = run.call(&Request::Head).unwrap();
        assert!(head.ok, "{}", head.value);
        run.wait_for_output(1, 2, ordinary + REFUSAL_OUTPUT_HEADROOM);
        if pq {
            assert_eq!(run.intake.pq_authentication.usage().unwrap().attempts, 8);
        }
        drop((fallback, bulk));
        let observed = run.finish();
        assert_eq!(observed.output_refusal_reservations, 1);
        assert_eq!(observed.output_admission_refusals, 1);
        assert_eq!(observed.output_serialization_failures, 0);
        assert_eq!(observed.completed_read, 1);
        assert_eq!(observed.mutation_cpu_reservations, 0);
        assert!(observed.peak_output_reserved_bytes <= MAX_OUTPUT_BYTES);
        assert_eq!(observed.output_reserved_bytes_after_shutdown, 0);
        assert_eq!(observed.read_grants_after_shutdown, 0);
    }
}
