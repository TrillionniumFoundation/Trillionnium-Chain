//! Real W1/thread-CPU controls for scheduling within the unchanged scalar account.
//! The original multi-process campaign remains the native liveness acceptance.
use super::super::PublicDispatchObservation;
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
    let (directory, settings, packet) = packet();
    let node =
        Mutex::new(Node::open(&directory.path().join("released-cpu-owner"), settings, 1).unwrap());
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
    // A completed actual shared-owner scope cannot disable this operation's
    // subsequent lock-free completion refill. All CPU below remains real W1.
    let held = crate::ingress::scope_node_owner(
        node.lock().unwrap(),
        Some(&operation.checkpoint_handle()),
    )
    .unwrap();
    operation.checkpoint().unwrap();
    drop(held);
    assert!(node.try_lock().is_ok());
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
            PublicDispatchObservation {
                observation: None,
                mutation_cpu: Some(&measurement),
                arithmetic_facts: None,
                w1_rejection_cache: None,
            },
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

#[test]
fn same_valid_w1_native_invalid_packet_cannot_reacquire_completion_priority() {
    use super::super::{
        public_dispatch, MutationCpuMeasurement, PaidMutationCpuPermit, PublicMetrics,
        PublicPolicy, PublicServer, Request,
    };
    use crate::ingress::DevelopmentIdentity;
    use trnm_crypto_primitives::pon_work;
    let (directory, settings, mut candidate) = packet();
    let node = Mutex::new(Node::open(&directory.path().join("receiver"), settings, 1).unwrap());
    let before = node.lock().unwrap().read_active().unwrap();
    let a: Vec<u32> = candidate.proof[4..4 + 4 * pon_work::CELLS]
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect();
    let b: Vec<u32> = candidate.proof[4 + 4 * pon_work::CELLS..4 + 8 * pon_work::CELLS]
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect();
    let prepared = pon_work::PreparedTask::new(&a, &b).unwrap();
    // Mine exactly one genuine full W1 for an intentionally wrong native State
    // commitment. Repeated request envelopes reuse this same acquired work.
    candidate.header.state[0] ^= 1;
    let mut attempts = 0;
    for nonce in 0..4096 {
        attempts += 1;
        candidate.header.nonce = nonce;
        candidate.proof = prepared.prove(candidate.header.challenge()).unwrap();
        if pon_work::precheck_proof_statement(
            candidate.header.challenge(),
            candidate.header.work_task,
            candidate.header.target,
            &candidate.proof,
        )
        .is_ok()
        {
            break;
        }
    }
    WorkCheckedPacket::verify(candidate.clone()).unwrap();
    let wire = hex::encode(candidate.encode().unwrap());
    let server = PublicServer::new(
        DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap(),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Mutex::new(PublicMetrics::default());
    let mut promotions = Vec::new();
    for _ in 0..2 {
        let cancelled = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(2);
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
                packet: wire.clone(),
            },
            deadline,
            &stop,
            &cancelled,
            &metrics,
            PublicDispatchObservation {
                observation: None,
                mutation_cpu: Some(&measurement),
                arithmetic_facts: None,
                w1_rejection_cache: None,
            },
        );
        promotions.push(server.mutation_cpu.lock().unwrap().verified_completions);
        permit.finish(&measurement, &server, &metrics).unwrap();
        assert!(
            matches!(&outcome, Err(error) if error.to_string() == "ROOT"
            && !error.requires_owner_stop()),
            "full-W1 native-invalid outcome changed: {outcome:?}"
        );
        assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
        assert!(node
            .lock()
            .unwrap()
            .packet(candidate.id().unwrap())
            .is_err());
    }
    let observed = metrics.into_inner().unwrap();
    assert_eq!(observed.work_started, 2);
    assert_eq!(observed.work_failed, 0);
    assert!(observed.mutation_cpu_charged_ns > 0);
    println!("same genuine W1 acquisition_attempts={attempts} requests=2 promotions={promotions:?} paid_cpu_ns={}",
        observed.mutation_cpu_charged_ns);
    assert_eq!(
        promotions,
        vec![1, 0],
        "one acquired W1 granted repeated completion priority"
    );
}

#[test]
fn completion_work_claim_is_atomic_across_real_verifiers_and_domain_clones() {
    let (_directory, _settings, packet) = packet();
    let domain = ServiceMutationCpuDomain::standalone();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let results = thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let domain = domain.clone();
                let packet = packet.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    let operation = domain.begin().unwrap();
                    bind(&operation, Duration::from_secs(2));
                    // Both original reservations exist before either promotion.
                    barrier.wait();
                    let checked = WorkCheckedPacket::verify_with_progress(packet, &mut |_| {
                        operation.checkpoint()
                    })
                    .unwrap();
                    barrier.wait();
                    operation.live.work_verified(&checked).unwrap();
                    let promoted = operation.live.state.lock().unwrap().verified_completion;
                    barrier.wait();
                    assert_eq!(domain.budget.lock().unwrap().verified_completions, 1);
                    barrier.wait();
                    (promoted, operation.finish())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|(promoted, _)| *promoted).count(), 1);
    assert!(results
        .iter()
        .all(|(_, receipt)| !receipt.accounting_unavailable && receipt.total_cpu_ns.unwrap() > 0));
    let observed = domain.observe_completion_work().unwrap();
    assert_eq!(
        (
            observed.retained_identities,
            observed.live_completions,
            observed.repeated_identity_skips
        ),
        (1, 0, 1)
    );
    assert!(
        domain
            .observe_actual_flow()
            .unwrap()
            .unwrap()
            .balance_identity_verified
    );
}

#[test]
fn completion_identity_survives_cancel_and_unknown_without_invalidating_retry() {
    let (_directory, _settings, packet) = packet();
    for unknown in [false, true] {
        let domain = ServiceMutationCpuDomain::standalone();
        let operation = domain.begin().unwrap();
        let cancelled = bind(&operation, Duration::from_secs(2));
        qualify(&operation, &packet);
        if unknown {
            operation
                .live
                .fail_next_sample
                .store(true, Ordering::Release);
        } else {
            cancelled.store(true, Ordering::Release);
        }
        assert!(operation.checkpoint().is_err());
        let receipt = operation.finish();
        assert_eq!(receipt.accounting_unavailable, unknown);
        let observed = domain.clone().observe_completion_work().unwrap();
        assert_eq!(
            (observed.retained_identities, observed.live_completions),
            (1, 0)
        );
        if unknown {
            assert!(!domain.accounting_available());
            assert!(domain.begin().is_err());
        } else {
            let retry = domain.begin().unwrap();
            bind(&retry, Duration::from_secs(2));
            qualify(&retry, &packet);
            assert!(!retry.live.state.lock().unwrap().verified_completion);
            assert!(!retry.finish().accounting_unavailable);
            assert_eq!(
                domain
                    .observe_completion_work()
                    .unwrap()
                    .repeated_identity_skips,
                1
            );
        }
    }
}

#[test]
fn full_completion_registry_keeps_all_markers_and_allows_real_native_admission() {
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
    let domain = server.mutation_cpu_domain();
    // A deterministic full-boundary fixture is not a throughput/attack receipt.
    // The request below still executes its actual full W1 and native admission.
    let checked = WorkCheckedPacket::verify(packet.clone()).unwrap();
    let actual_identity = checked.completion_identity().unwrap();
    let full_before = {
        let mut budget = domain.budget.lock().unwrap();
        for index in 0..COMPLETION_WORK_CAPACITY {
            let identity = trnm_protocol::pon_wire::hash(
                b"r13-full-boundary-fixture",
                &[&(index as u64).to_le_bytes()],
            );
            assert_ne!(identity, actual_identity);
            budget.completion_work[index] = identity;
        }
        budget.completion_work_len = COMPLETION_WORK_CAPACITY;
        budget.completion_work.clone()
    };
    let stop = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + Duration::from_secs(2);
    let metrics = Mutex::new(PublicMetrics::default());
    let permit =
        PaidMutationCpuPermit::acquire_before(&server, &metrics, deadline, &stop, &cancelled)
            .unwrap();
    permit
        .live
        .bind_public_request(deadline, stop.clone(), cancelled.clone())
        .unwrap();
    let measurement = MutationCpuMeasurement::for_permit(Some(&permit));
    let result = public_dispatch(
        &node,
        Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        },
        deadline,
        &stop,
        &cancelled,
        &metrics,
        PublicDispatchObservation {
            observation: None,
            mutation_cpu: Some(&measurement),
            arithmetic_facts: None,
            w1_rejection_cache: None,
        },
    )
    .unwrap();
    assert_eq!(result["block"], hex::encode(packet.id().unwrap()));
    assert_eq!(
        node.lock().unwrap().read_active().unwrap().0,
        packet.id().unwrap()
    );
    permit.finish(&measurement, &server, &metrics).unwrap();
    let observed = domain.observe_completion_work().unwrap();
    assert_eq!(
        (
            observed.retained_identities,
            observed.live_completions,
            observed.full_capacity_skips
        ),
        (COMPLETION_WORK_CAPACITY, 0, 1)
    );
    assert_eq!(domain.budget.lock().unwrap().completion_work, full_before);
    assert_eq!(observed.identity_storage_bytes, 4096 * 32);
    assert!(
        !observed.evicts_live_epoch_identities
            && !observed.survives_process_restart
            && !observed.full_capacity_disables_ordinary_verification
    );
    // Actual restart is an explicit new volatile epoch, never permanent-once.
    let cold = PaidMutationCpuBudget::cold_start();
    assert_eq!((cold.credit_ns, cold.completion_work_len), (0, 0));
}

#[test]
fn same_verified_w1_with_changed_transaction_body_is_rejected_before_promotion() {
    use super::super::{
        public_dispatch, MutationCpuMeasurement, PaidMutationCpuPermit, PublicMetrics,
        PublicPolicy, PublicServer, Request,
    };
    use crate::ingress::DevelopmentIdentity;
    use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
    use trnm_protocol::pon_wire::{hash, Envelope};
    let (directory, settings, original) = packet();
    let node =
        Mutex::new(Node::open(&directory.path().join("receiver"), settings.clone(), 1).unwrap());
    let before = node.lock().unwrap().read_active().unwrap();
    let server = PublicServer::new(
        DevelopmentIdentity::from_secret_hex(&hex::encode([71; 32])).unwrap(),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
    )
    .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Mutex::new(PublicMetrics::default());
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    for amount in [1_u64, 2] {
        let mut payload = crate::development_public(1).unwrap().to_vec();
        payload.extend(amount.to_le_bytes());
        let mut envelope = Envelope {
            network: settings.network(),
            sender: crate::development_public(0).unwrap(),
            nonce: 1,
            expiry: 1000,
            fee_limit: 1_000_000,
            tag: 1,
            payload,
            signature: [0; 64],
        };
        envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
            .unwrap()
            .try_into()
            .unwrap();
        let mut changed = original.clone();
        changed.transactions = vec![envelope.encode().unwrap()];
        assert_eq!(changed.header.encode(), original.header.encode());
        assert_eq!(changed.proof, original.proof);
        // W1 alone intentionally has no body admission authority. This proves
        // the adversarial body really reuses the one actually valid proof.
        WorkCheckedPacket::verify(changed.clone()).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let deadline = Instant::now() + Duration::from_secs(2);
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
                packet: hex::encode(changed.encode().unwrap()),
            },
            deadline,
            &stop,
            &cancelled,
            &metrics,
            PublicDispatchObservation {
                observation: None,
                mutation_cpu: Some(&measurement),
                arithmetic_facts: None,
                w1_rejection_cache: None,
            },
        );
        permit.finish(&measurement, &server, &metrics).unwrap();
        assert!(matches!(&outcome, Err(error) if error.to_string() == "ROOT"
            && !error.requires_owner_stop()));
        let observed = server
            .mutation_cpu_domain()
            .observe_completion_work()
            .unwrap();
        assert_eq!(
            (observed.retained_identities, observed.live_completions),
            (0, 0)
        );
        // Making that changed body consistent changes the W1 statement; the
        // previously acquired proof no longer verifies under the new header.
        changed.header.transactions = crate::sequence_root("transactions", &changed.transactions);
        assert!(WorkCheckedPacket::verify(changed).is_err());
    }
    let observed = metrics.into_inner().unwrap();
    assert_eq!((observed.work_started, observed.work_finished), (0, 0));
    assert_eq!(observed.mutation_cpu_reservations, 2);
    assert!(observed.mutation_cpu_charged_ns > 0);
    assert_eq!(node.lock().unwrap().read_active().unwrap(), before);
}

#[test]
fn exclusive_history_refill_observes_original_resource_cancellation_without_new_credit() {
    let (_directory, _settings, packet) = packet();
    let domain = ServiceMutationCpuDomain::cold_remote_history_epoch();
    let deadline = Instant::now() + Duration::from_secs(5);
    let operation = loop {
        match domain.begin() {
            Ok(operation) => break operation,
            Err(error) => {
                assert!(error.is(crate::ErrorCode::PublicMutationCpuBudget));
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(2));
            }
        }
    };
    operation.bind_history_request(deadline).unwrap();
    let checked = WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |_| {
        operation.history_checkpoint(false, &|| Ok(()))
    })
    .unwrap();
    operation.history_work_verified(&checked).unwrap();
    let saw_real_deficit = AtomicBool::new(false);
    let resource = || {
        ensure(Instant::now() < deadline, "PUBLIC_REQUEST_DEADLINE")?;
        if domain.observe()?.stored_credit_ns < -i128::from(MUTATION_CPU_START_RESERVE_NS) {
            saw_real_deficit.store(true, Ordering::Release);
            return Err(crate::Error::new(crate::ErrorCode::PublicRequestCancelled));
        }
        Ok(())
    };
    // Actual full native W1 CPU reaches a real refill wait. This repeated
    // arithmetic is a cancellation/meter control, not a network attack claim.
    loop {
        match WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |_| {
            operation.history_checkpoint(false, &resource)
        }) {
            Ok(_) => assert!(Instant::now() < deadline),
            Err(error) => {
                assert!(error.is(crate::ErrorCode::PublicRequestCancelled));
                break;
            }
        }
    }
    assert!(saw_real_deficit.load(Ordering::Acquire));
    assert!(Instant::now() < deadline);
    let receipt = operation.finish();
    assert!(!receipt.accounting_unavailable);
    assert!(receipt.total_cpu_ns.unwrap() > MUTATION_CPU_START_RESERVE_NS);
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(flow.initial_credit_ns, 0);
    assert_eq!(flow.booked_reservation_ns, 0);
    assert_eq!(flow.paid_cpu_debit_ns, receipt.total_cpu_ns.unwrap());
    assert!(flow.balance_identity_verified);
    println!(
        "{}",
        serde_json::json!({"schema":"history-resource-cancellation-real-refill-v1", "receipt":receipt, "flow":flow})
    );
}

#[test]
fn shared_submit_cpu_refill_never_waits_while_holding_native_owner() {
    use std::sync::{atomic::AtomicUsize, TryLockError};
    use trnm_mvcc_fee::pon_executor::ExecutionControl;

    let (directory, settings, packet) = packet();
    let node =
        Mutex::new(Node::open(&directory.path().join("held-cpu-receiver"), settings, 1).unwrap());
    let before = node.lock().unwrap().read_active().unwrap();
    let packet_id = packet.id().unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    bind(&operation, Duration::from_secs(5));
    let checkpoint = operation.checkpoint_handle();
    let verified = AtomicBool::new(false);
    let injected = AtomicBool::new(false);
    let wait_checks = AtomicUsize::new(0);
    let execution_progress = |_| {
        if verified.load(Ordering::Acquire)
            && matches!(node.try_lock(), Err(TryLockError::WouldBlock))
            && !injected.swap(true, Ordering::AcqRel)
        {
            // Deterministic scheduling control, NOT a measured cost sample.
            // Real full W1 created the private completion capability. Only
            // the available allowance is forced here; actual CPU still settles.
            let mut budget = domain.budget.lock().unwrap();
            budget.credit_ns = -i128::from(MUTATION_CPU_BURST_NS);
            budget.updated = Instant::now();
            budget.flow = None;
        }
        if injected.load(Ordering::Acquire) {
            // The second resource check precedes the refill sleep. Refuse it
            // deterministically so the old bug cannot hang this regression.
            operation.history_checkpoint(false, &|| {
                ensure(
                    wait_checks.fetch_add(1, Ordering::AcqRel) == 0,
                    "TEST_REFILL_WAIT_UNDER_OWNER",
                )
            })
        } else {
            operation.checkpoint()
        }
    };
    let result = crate::ingress::dispatch_shared_with_execution_observation(
        &node,
        crate::ingress::Request::Submit {
            packet: hex::encode(packet.encode().unwrap()),
        },
        &mut |_| operation.checkpoint(),
        |packet| {
            let checked =
                WorkCheckedPacket::verify_with_progress(packet, &mut |_| operation.checkpoint())?;
            operation.live.work_verified(&checked)?;
            verified.store(true, Ordering::Release);
            Ok(checked)
        },
        &ExecutionControl::new(&execution_progress, operation.worker_accounting()),
        crate::ingress::SubmitDispatchContext {
            public_proof_before_unowned_task: true,
            termination_cpu: Some(&checkpoint),
            ..crate::ingress::SubmitDispatchContext::default()
        },
    );
    let receipt = operation.finish();
    let error = result.expect_err("a held-owner deficit must refuse without waiting");
    println!(
        "{}",
        serde_json::json!({"schema":"native-submit-owner-cpu-wait-control-v1",
            "real_full_w1_verified":verified.load(Ordering::Acquire),
            "injected_credit_deficit":injected.load(Ordering::Acquire),
            "resource_checks":wait_checks.load(Ordering::Acquire),
            "result":error.to_string(),"receipt":receipt,
            "service_qualified":false})
    );
    assert!(verified.load(Ordering::Acquire));
    assert!(injected.load(Ordering::Acquire));
    assert!(
        error.is(crate::ErrorCode::PublicMutationCpuBudget),
        "shared native owner entered the refill-wait path: {error}"
    );
    assert_eq!(wait_checks.load(Ordering::Acquire), 1);
    assert!(!receipt.accounting_unavailable);
    assert!(receipt.live_refused);
    assert!(receipt.total_cpu_ns.is_some_and(|paid| paid > 0));
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    assert_eq!(
        domain
            .observe_completion_work()
            .unwrap()
            .retained_identities,
        1
    );
    let owner = node
        .try_lock()
        .expect("refusal must release the actual writer");
    assert_eq!(owner.read_active().unwrap(), before);
    assert!(owner.packet(packet_id).is_err());
}

// Synthetic allowance controls below are scheduling regressions only. They
// keep real proof capabilities and measured thread settlement, but deliberately
// omit the cost-flow diagnostic after forcing credit. They are not service or
// attack-cost measurements.
fn force_completion_deficit(domain: &ServiceMutationCpuDomain) {
    let mut budget = domain.budget.lock().unwrap();
    budget.credit_ns = -i128::from(MUTATION_CPU_BURST_NS);
    budget.updated = Instant::now();
    budget.flow = None;
}

#[test]
fn held_node_cpu_scope_reaches_joined_workers_without_refill_wait() {
    use std::sync::{atomic::AtomicUsize, TryLockError};

    let (directory, settings, packet) = packet();
    let node =
        Mutex::new(Node::open(&directory.path().join("worker-cpu-owner"), settings, 1).unwrap());
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    bind(&operation, Duration::from_secs(5));
    qualify(&operation, &packet);
    let checkpoint = operation.checkpoint_handle();
    let held = crate::ingress::scope_node_owner(node.lock().unwrap(), Some(&checkpoint)).unwrap();
    force_completion_deficit(&domain);
    let resource_checks = AtomicUsize::new(0);
    let error = thread::scope(|scope| {
        let accounting = operation.worker_accounting();
        let child_checkpoint = &checkpoint;
        let child_resource_checks = &resource_checks;
        let child_node = &node;
        let worker = scope.spawn(move || {
            let _interval = accounting.worker_started();
            child_checkpoint.history_checkpoint(false, &|| {
                assert!(matches!(
                    child_node.try_lock(),
                    Err(TryLockError::WouldBlock)
                ));
                ensure(
                    child_resource_checks.fetch_add(1, Ordering::AcqRel) == 0,
                    "TEST_WORKER_REFILL_WAIT_UNDER_OWNER",
                )
            })
        });
        accounting.worker_spawn_succeeded();
        worker.join().unwrap().unwrap_err()
    });
    assert!(error.is(crate::ErrorCode::PublicMutationCpuBudget));
    assert_eq!(resource_checks.load(Ordering::Acquire), 1);
    assert!(matches!(node.try_lock(), Err(TryLockError::WouldBlock)));
    drop(held);
    assert!(node.try_lock().is_ok());
    let receipt = operation.finish();
    assert!(!receipt.accounting_unavailable);
    assert!(receipt.live_refused);
    assert_eq!(
        (
            receipt.spawned_workers,
            receipt.started_workers,
            receipt.finished_workers,
            receipt.known_workers
        ),
        (1, 1, 1, 1)
    );
    assert!(receipt.scoped_worker_cpu_ns.is_some_and(|paid| paid > 0));
    assert_eq!(domain.observe().unwrap().in_flight, 0);
}

#[test]
fn held_node_cpu_scope_does_not_disable_another_requests_refill() {
    use std::sync::atomic::AtomicUsize;

    let (directory, settings, packet) = packet();
    let producer = Node::open(
        &directory.path().join("second-cpu-producer"),
        settings.clone(),
        1,
    )
    .unwrap();
    let second_packet = producer
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            settings.genesis_time() + 3,
            4096,
        )
        .unwrap();
    let node =
        Mutex::new(Node::open(&directory.path().join("separate-cpu-owner"), settings, 1).unwrap());
    let domain = ServiceMutationCpuDomain::standalone();
    // Both original reservations precede promotion. These are two real,
    // distinct complete W1 identities in the SAME shared CPU domain.
    let first = domain.begin().unwrap();
    let second = domain.begin().unwrap();
    bind(&first, Duration::from_secs(5));
    bind(&second, Duration::from_secs(5));
    qualify(&first, &packet);
    qualify(&second, &second_packet);
    assert_eq!(
        domain.observe_completion_work().unwrap().live_completions,
        2
    );
    let held =
        crate::ingress::scope_node_owner(node.lock().unwrap(), Some(&first.checkpoint_handle()))
            .unwrap();
    force_completion_deficit(&domain);
    let resource_checks = AtomicUsize::new(0);
    let error = second
        .history_checkpoint(false, &|| {
            ensure(
                resource_checks.fetch_add(1, Ordering::AcqRel) == 0,
                "TEST_UNHELD_REQUEST_REACHED_ORIGINAL_REFILL",
            )
        })
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "TEST_UNHELD_REQUEST_REACHED_ORIGINAL_REFILL"
    );
    assert_eq!(resource_checks.load(Ordering::Acquire), 2);
    let second_receipt = second.finish();
    assert!(!second_receipt.accounting_unavailable && !second_receipt.live_refused);
    drop(held);
    let first_receipt = first.finish();
    assert!(!first_receipt.accounting_unavailable);
    assert!(node.try_lock().is_ok());
    assert_eq!(domain.observe().unwrap().in_flight, 0);
    assert_eq!(
        domain.observe_completion_work().unwrap().live_completions,
        0
    );
}

#[test]
fn node_owner_registration_refuses_a_worker_already_entering_refill() {
    use std::sync::atomic::AtomicUsize;

    let (directory, settings, packet) = packet();
    let node = Mutex::new(
        Node::open(&directory.path().join("waiting-worker-owner"), settings, 1).unwrap(),
    );
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    bind(&operation, Duration::from_secs(5));
    qualify(&operation, &packet);
    let checkpoint = operation.checkpoint_handle();
    force_completion_deficit(&domain);
    let resource_checks = AtomicUsize::new(0);
    let (reached_wait, registration_error, writer_released, worker_error) =
        thread::scope(|scope| {
            let accounting = operation.worker_accounting();
            let child_checkpoint = &checkpoint;
            let child_checks = &resource_checks;
            let (entered, entered_rx) = mpsc::channel();
            let (resume, resume_rx) = mpsc::channel();
            let resume_rx = Mutex::new(resume_rx);
            let worker = scope.spawn(move || {
                let _interval = accounting.worker_started();
                child_checkpoint.history_checkpoint(false, &|| {
                    match child_checks.fetch_add(1, Ordering::AcqRel) {
                        0 => Ok(()),
                        1 => {
                            // This callback is after observe_with_control decided
                            // that the request could wait, but before its sleep.
                            // Two bounded channels form the deterministic barrier.
                            entered
                                .send(())
                                .map_err(|_| crate::Error::from("TEST_WAIT_BARRIER_SEND"))?;
                            resume_rx
                                .lock()
                                .map_err(|_| crate::Error::from("TEST_WAIT_BARRIER_LOCK"))?
                                .recv_timeout(Duration::from_secs(5))
                                .map_err(|_| crate::Error::from("TEST_WAIT_BARRIER_TIMEOUT"))?;
                            Err("TEST_WORKER_REFILL_RESUMED".into())
                        }
                        _ => Err("TEST_UNEXPECTED_REFILL_RESOURCE_CHECK".into()),
                    }
                })
            });
            accounting.worker_spawn_succeeded();
            let reached_wait = entered_rx.recv_timeout(Duration::from_secs(5)).is_ok();
            let registration_error = if reached_wait {
                match crate::ingress::scope_node_owner(node.lock().unwrap(), Some(&checkpoint)) {
                    Ok(held) => {
                        // Release even on the old implementation, so the red
                        // regression reports the race without leaving a live join.
                        drop(held);
                        None
                    }
                    Err(error) => Some(error),
                }
            } else {
                None
            };
            let writer_released = node.try_lock().is_ok();
            // Complete cleanup before assertions on either implementation.
            let _ = resume.send(());
            let worker_error = worker.join().unwrap().unwrap_err();
            (
                reached_wait,
                registration_error,
                writer_released,
                worker_error,
            )
        });
    let receipt = operation.finish();
    println!(
        "{}",
        serde_json::json!({"schema":"node-owner-worker-wait-race-control-v1",
            "real_full_w1_verified":true,"injected_credit_deficit":true,
            "worker_paused_after_wait_decision":reached_wait,
            "registration_error":registration_error.as_ref().map(ToString::to_string),
            "writer_released":writer_released,"receipt":receipt,
            "service_qualified":false})
    );
    assert!(reached_wait);
    assert_eq!(resource_checks.load(Ordering::Acquire), 2);
    assert_eq!(worker_error.to_string(), "TEST_WORKER_REFILL_RESUMED");
    assert!(registration_error
        .expect("a worker already entering refill must prevent owner registration")
        .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    assert!(writer_released);
    assert!(receipt.accounting_unavailable);
    assert!(!domain.accounting_available());
    assert!(domain
        .begin()
        .err()
        .unwrap()
        .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    assert!(node.try_lock().is_ok());
}

#[test]
fn node_cpu_scope_lifecycle_failures_fence_the_original_account() {
    let (directory, settings, _packet) = packet();
    let node =
        Mutex::new(Node::open(&directory.path().join("failed-cpu-owner"), settings, 1).unwrap());
    for overflow in [true, false] {
        let domain = ServiceMutationCpuDomain::standalone();
        let operation = domain.begin().unwrap();
        let checkpoint = operation.checkpoint_handle();
        let receipt = if overflow {
            operation.live.state.lock().unwrap().node_owner_scopes = u32::MAX;
            let error = crate::ingress::scope_node_owner(node.lock().unwrap(), Some(&checkpoint))
                .err()
                .expect("scope overflow must refuse without wrapping");
            assert!(error.is(crate::ErrorCode::PublicMutationCpuUnavailable));
            assert!(node.try_lock().is_ok());
            operation.finish()
        } else {
            let held =
                crate::ingress::scope_node_owner(node.lock().unwrap(), Some(&checkpoint)).unwrap();
            // Ending the paid operation before its real guard is released
            // must not make a still-held execution scope available for reuse.
            let receipt = operation.finish();
            drop(held);
            receipt
        };
        assert!(receipt.accounting_unavailable);
        assert!(node.try_lock().is_ok());
        assert!(!domain.accounting_available());
        assert!(domain
            .begin()
            .err()
            .unwrap()
            .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    }
}
