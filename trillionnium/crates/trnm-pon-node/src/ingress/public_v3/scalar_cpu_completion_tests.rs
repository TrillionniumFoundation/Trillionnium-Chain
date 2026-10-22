//! Real W1/thread-CPU controls for scheduling within the unchanged scalar account.
//! The original multi-process campaign remains the native liveness acceptance.
use super::*;
use crate::{store::WorkCheckedPacket, Node, Packet, Settings};
use std::sync::mpsc;

fn packet() -> (tempfile::TempDir, Settings, Packet) {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let node = Node::open(&directory.path().join("producer"), settings.clone(), 1).unwrap();
    let packet = node
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            settings.genesis_time() + 2,
            4096,
        )
        .unwrap();
    WorkCheckedPacket::verify(packet.clone()).unwrap();
    (directory, settings, packet)
}
fn bind(operation: &ServiceMutationCpuOperation, lifetime: Duration) -> Arc<AtomicBool> {
    let cancelled = Arc::new(AtomicBool::new(false));
    operation
        .live
        .bind_public_request(
            Instant::now() + lifetime,
            Arc::new(AtomicBool::new(false)),
            cancelled.clone(),
        )
        .unwrap();
    cancelled
}
fn qualify(operation: &ServiceMutationCpuOperation, packet: &Packet) {
    let checked =
        WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |_| operation.checkpoint())
            .unwrap();
    operation.live.work_verified(&checked).unwrap();
}

#[test]
fn complete_actual_w1_blocks_new_probes_without_new_credit_and_releases_once() {
    let (_directory, _settings, packet) = packet();
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    bind(&operation, Duration::from_secs(3));
    qualify(&operation, &packet);
    let during = domain.observe().unwrap();
    assert!(during.stored_credit_ns > i128::from(MUTATION_CPU_START_RESERVE_NS));
    assert_eq!(during.in_flight, 1);
    assert_eq!(domain.budget.lock().unwrap().verified_completions, 1);
    assert_eq!(
        domain.begin().err().unwrap().to_string(),
        "PUBLIC_MUTATION_CPU_BUDGET"
    );
    let receipt = operation.finish();
    assert!(!receipt.accounting_unavailable);
    assert!(receipt.total_cpu_ns.unwrap() > 0);
    assert_eq!(domain.budget.lock().unwrap().verified_completions, 0);
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert!(flow.balance_identity_verified);
    assert_eq!(flow.booked_reservation_ns, 0);
    assert_eq!(flow.paid_cpu_debit_ns, receipt.total_cpu_ns.unwrap());
    assert!(flow.remaining_paid_credit_ns <= i128::from(MUTATION_CPU_BURST_NS));
    assert!(!domain.begin().unwrap().finish().accounting_unavailable);
}

#[test]
fn actual_w1_cpu_completion_waits_for_original_refill_and_preserves_balance_identity() {
    let (_directory, _settings, packet) = packet();
    let domain = ServiceMutationCpuDomain {
        budget: Arc::new(Mutex::new(PaidMutationCpuBudget::cold_start())),
    };
    let admission_deadline = Instant::now() + Duration::from_secs(2);
    let operation = loop {
        match domain.begin() {
            Ok(operation) => break operation,
            Err(error) => {
                assert_eq!(error.to_string(), "PUBLIC_MUTATION_CPU_BUDGET");
                assert!(Instant::now() < admission_deadline);
                thread::sleep(Duration::from_millis(2));
            }
        }
    };
    let start = Instant::now();
    bind(&operation, Duration::from_secs(5));
    qualify(&operation, &packet);
    // Exercise real original W1 CPU, never a busy loop, fabricated time sample
    // or negative-balance assignment. This checks the meter's continuation,
    // not a claim that repeated proof replay is useful native application work.
    let actual = ThreadCpuStamp::start().unwrap();
    let mut samples = 0;
    while operation.live.state.lock().unwrap().charged_ns < 250_000_000 {
        WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |_| operation.checkpoint())
            .unwrap();
        samples += 1;
        assert!(start.elapsed() < Duration::from_secs(5));
    }
    let replay_cpu = actual.finish().unwrap();
    assert!(samples > 1 && replay_cpu > 100_000_000);
    let receipt = operation.finish();
    assert!(!receipt.accounting_unavailable && !receipt.live_refused);
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(flow.initial_credit_ns, 0);
    assert_eq!(flow.booked_reservation_ns, 0);
    assert_eq!(flow.paid_cpu_debit_ns, receipt.total_cpu_ns.unwrap());
    assert_eq!(
        flow.remaining_paid_credit_ns,
        i128::from(flow.credited_refill_ns)
            - i128::from(flow.paid_cpu_debit_ns)
            - i128::from(flow.settlement_discard_ns)
    );
    assert!(start.elapsed() >= Duration::from_millis(400));
    assert_eq!(domain.budget.lock().unwrap().verified_completions, 0);
    println!(
        "verified completion actual W1 replays={samples} cpu_ns={replay_cpu} flow={}",
        serde_json::to_string(&flow).unwrap()
    );
}

#[test]
fn already_running_probe_cannot_spend_beyond_its_original_quantum_during_completion() {
    let (_directory, _settings, packet) = packet();
    let domain = ServiceMutationCpuDomain::standalone();
    let probe = domain.begin().unwrap();
    let (ready, started) = mpsc::sync_channel(0);
    let (release, finish) = mpsc::channel();
    thread::scope(|scope| {
        let completion_domain = &domain;
        let completion_packet = &packet;
        let worker = scope.spawn(move || {
            let completion = completion_domain.begin().unwrap();
            bind(&completion, Duration::from_secs(3));
            qualify(&completion, completion_packet);
            ready.send(()).unwrap();
            // A preceding assertion failure must release the worker within a
            // finite interval, rather than leave the regression test hanging.
            let released = finish.recv_timeout(Duration::from_secs(3));
            let receipt = completion.finish();
            assert!(
                released.is_ok(),
                "probe did not finish within its original test bound"
            );
            receipt
        });
        started.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(domain.budget.lock().unwrap().verified_completions, 1);
        let actual_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |_| {
                probe.checkpoint()
            }) {
                Ok(_) => assert!(Instant::now() < actual_deadline),
                Err(error) => {
                    assert_eq!(error.to_string(), "PUBLIC_MUTATION_CPU_BUDGET");
                    break;
                }
            }
        }
        let measured = probe.live.state.lock().unwrap().charged_ns;
        assert!(measured > MUTATION_CPU_START_RESERVE_NS);
        // Global credit is plentiful: this refusal protects completion refills,
        // rather than falsely claiming that the entire budget was exhausted.
        assert!(domain.observe().unwrap().stored_credit_ns > 1_000_000_000);
        assert_eq!(
            probe.checkpoint().unwrap_err().to_string(),
            "PUBLIC_MUTATION_CPU_BUDGET"
        );
        assert!(!probe.finish().accounting_unavailable);
        release.send(()).unwrap();
        assert!(!worker.join().unwrap().accounting_unavailable);
    });
    assert_eq!(domain.budget.lock().unwrap().verified_completions, 0);
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    assert!(
        domain
            .observe_actual_flow()
            .unwrap()
            .unwrap()
            .balance_identity_verified
    );
}

#[test]
fn completion_keeps_original_cancellation_deadline_and_unknown_clock_fences() {
    let (_directory, _settings, packet) = packet();
    for mode in 0..3 {
        let domain = ServiceMutationCpuDomain::standalone();
        let operation = domain.begin().unwrap();
        let cancelled = bind(&operation, Duration::from_millis(300));
        qualify(&operation, &packet);
        assert!(operation
            .live
            .bind_public_request(
                Instant::now() + Duration::from_secs(10),
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false))
            )
            .is_err());
        let expected = match mode {
            0 => {
                cancelled.store(true, Ordering::Release);
                "PUBLIC_REQUEST_CANCELLED"
            }
            1 => {
                thread::sleep(Duration::from_millis(320));
                "PUBLIC_REQUEST_DEADLINE"
            }
            _ => {
                operation
                    .live
                    .fail_next_sample
                    .store(true, Ordering::Release);
                "PUBLIC_MUTATION_CPU_UNAVAILABLE"
            }
        };
        assert_eq!(operation.checkpoint().unwrap_err().to_string(), expected);
        let receipt = operation.finish();
        assert_eq!(receipt.accounting_unavailable, mode == 2);
        assert_eq!(domain.budget.lock().unwrap().verified_completions, 0);
        if mode == 2 {
            assert_eq!(
                domain.begin().err().unwrap().to_string(),
                "PUBLIC_MUTATION_CPU_UNAVAILABLE"
            );
        } else {
            assert!(receipt.total_cpu_ns.unwrap() > 0);
            assert!(
                domain
                    .observe_actual_flow()
                    .unwrap()
                    .unwrap()
                    .balance_identity_verified
            );
        }
    }
}

#[test]
fn only_fresh_successful_native_w1_promotes_not_false_product_or_existing_packet() {
    use super::super::{
        public_dispatch, MutationCpuMeasurement, PaidMutationCpuPermit, PublicMetrics,
        PublicPolicy, PublicServer, Request,
    };
    use crate::ingress::DevelopmentIdentity;
    let (directory, settings, packet) = packet();
    let node = Mutex::new(Node::open(&directory.path().join("receiver"), settings, 1).unwrap());
    let server = PublicServer::new(
        DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap(),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Mutex::new(PublicMetrics::default());
    let mut false_product = packet.clone();
    let at = 4 + 8 * trnm_crypto_primitives::pon_work::CELLS;
    let value = u32::from_le_bytes(false_product.proof[at..at + 4].try_into().unwrap());
    let changed = ((u64::from(value) + 1) % 4_294_967_291) as u32;
    false_product.proof[at..at + 4].copy_from_slice(&changed.to_le_bytes());
    for (index, candidate) in [false_product, packet.clone(), packet]
        .into_iter()
        .enumerate()
    {
        let cancelled = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(5);
        let permit =
            PaidMutationCpuPermit::acquire_before(&server, &metrics, deadline, &stop, &cancelled)
                .unwrap();
        permit
            .live
            .bind_public_request(deadline, stop.clone(), cancelled.clone())
            .unwrap();
        let measurement = MutationCpuMeasurement::for_permit(Some(&permit));
        let outcome = public_dispatch(
            &node,
            Request::Submit {
                packet: hex::encode(candidate.encode().unwrap()),
            },
            deadline,
            &stop,
            &cancelled,
            &metrics,
            (None, Some(&measurement)),
        );
        if index == 0 {
            assert_eq!(outcome.unwrap_err().to_string(), "WORK:Product");
        } else {
            assert!(
                outcome.is_ok(),
                "native completion/replay failed: {outcome:?}"
            );
        }
        assert_eq!(
            server.mutation_cpu.lock().unwrap().verified_completions,
            usize::from(index == 1)
        );
        permit.finish(&measurement, &server, &metrics).unwrap();
        assert_eq!(server.mutation_cpu.lock().unwrap().verified_completions, 0);
    }
    let metrics = metrics.into_inner().unwrap();
    assert_eq!(metrics.work_started, 2);
    assert_eq!(metrics.work_failed, 1);
    assert_eq!(metrics.mutation_cpu_clock_failures, 0);
}
