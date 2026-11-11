//! Actual W1/thread-CPU controls for the History writer handoff. These are
//! component checks, not a complete service campaign or a commit-cost bound.
use super::*;
use crate::{store::WorkCheckedPacket, Node, Packet, Settings};
use std::sync::{atomic::AtomicUsize, mpsc};

fn packet() -> (tempfile::TempDir, Packet) {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let node = Node::open(directory.path(), settings.clone(), 1).unwrap();
    let packet = node
        .make(
            settings.genesis(),
            vec![],
            crate::development_public(0).unwrap(),
            settings.genesis_time() + 2,
            4096,
        )
        .unwrap();
    (directory, packet)
}

fn alive(deadline: Instant) -> Result<()> {
    ensure(Instant::now() < deadline, "PUBLIC_REQUEST_DEADLINE")
}

fn begin(domain: &ServiceMutationCpuDomain, deadline: Instant) -> ServiceMutationCpuOperation {
    loop {
        alive(deadline).expect("cold fixture missed its original deadline");
        match domain.begin() {
            Ok(operation) => {
                operation.bind_history_request(deadline).unwrap();
                return operation;
            }
            Err(error) => {
                assert!(error.is(crate::ErrorCode::PublicMutationCpuBudget));
                thread::sleep(
                    Duration::from_millis(2)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        }
    }
}

fn qualify(operation: &ServiceMutationCpuOperation, packet: &Packet, deadline: Instant) {
    let checked = WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |_| {
        operation.history_checkpoint(false, &|| alive(deadline))
    })
    .unwrap();
    operation.history_work_verified(&checked).unwrap();
}

fn consume_free_credit(
    domain: &ServiceMutationCpuDomain,
    operation: &ServiceMutationCpuOperation,
    packet: &Packet,
    deadline: Instant,
) -> u64 {
    let mut replays = 0;
    while domain.observe().unwrap().stored_credit_ns >= -20_000_000 {
        alive(deadline).expect("actual free-credit depletion was not reached");
        WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |_| {
            operation.history_checkpoint(false, &|| alive(deadline))
        })
        .unwrap();
        replays += 1;
    }
    // Qualifying the real proof may itself already consume this headroom on a
    // slower runner. Keep that actual charged work; do not require extra load.
    assert!(operation.live.state.lock().unwrap().charged_ns > 0);
    let balance = domain.observe().unwrap();
    assert!(balance.stored_credit_ns < 0);
    assert!(balance.stored_credit_ns >= -i128::from(balance.start_reserve_ns));
    replays
}

fn assert_unlocked(operation: &ServiceMutationCpuOperation, domain: &ServiceMutationCpuDomain) {
    assert!(operation.live.state.try_lock().is_ok());
    assert!(domain.budget.try_lock().is_ok());
}

fn consume_unobserved_paid_balance(
    domain: &ServiceMutationCpuDomain,
    packet: &Packet,
    deadline: Instant,
) {
    let actual = ThreadCpuStamp::start().unwrap();
    let mut replay_cpu = 0;
    loop {
        alive(deadline).expect("actual global deficit fixture expired");
        let sample = ThreadCpuStamp::start().unwrap();
        WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |_| alive(deadline)).unwrap();
        replay_cpu += sample.finish().unwrap();
        let credit = domain.observe_credit_freshness().unwrap().unwrap();
        if i128::from(replay_cpu) > credit.projected_paid_credit_ns + 25_000_000 {
            break;
        }
    }
    assert!(actual.finish().unwrap() >= replay_cpu);
}

#[test]
fn history_writer_handoff_waits_for_original_free_credit_and_preserves_other_reserve() {
    let (_directory, packet) = packet();
    let domain = ServiceMutationCpuDomain::cold_remote_history_epoch();
    let deadline = Instant::now() + Duration::from_secs(5);
    let (ready_tx, ready_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    thread::scope(|scope| {
        // An actual independent owner thread buys its original quantum before
        // this request qualifies. No overlapping owner interval is double paid.
        let other_domain = &domain;
        let other = scope.spawn(move || {
            let operation = begin(other_domain, deadline);
            ready_tx.send(()).unwrap();
            let release = release_rx.recv_timeout(Duration::from_secs(5));
            let receipt = operation.finish();
            assert!(
                release.is_ok(),
                "handoff fixture did not release its other owner"
            );
            receipt
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let operation = begin(&domain, deadline);
        qualify(&operation, &packet, deadline);
        assert!(operation.live.state.lock().unwrap().verified_completion);
        let replays = consume_free_credit(&domain, &operation, &packet, deadline);
        let before = domain.observe_actual_flow().unwrap().unwrap();
        assert_eq!(
            before.booked_reservation_ns,
            2 * MUTATION_CPU_START_RESERVE_NS
        );
        assert_eq!(before.live_owners, 2);
        let checks = AtomicUsize::new(0);
        operation
            .checkpoint_handle()
            .history_prepare_writer(&|| {
                assert_unlocked(&operation, &domain);
                checks.fetch_add(1, Ordering::SeqCst);
                alive(deadline)
            })
            .unwrap();
        let after = domain.observe_actual_flow().unwrap().unwrap();
        assert!(checks.load(Ordering::SeqCst) > 1);
        assert!(after.stored_credit_ns >= 0);
        assert_eq!(after.booked_reservation_ns, before.booked_reservation_ns);
        assert_eq!(after.live_owners, before.live_owners);
        assert!(after.credited_refill_ns > before.credited_refill_ns);
        assert!(after.paid_cpu_debit_ns > before.paid_cpu_debit_ns);
        assert!(after.remaining_paid_credit_ns >= i128::from(after.booked_reservation_ns));
        assert_eq!(domain.budget.lock().unwrap().verified_completions, 1);
        let receipt = operation.finish();
        release_tx.send(()).unwrap();
        let other_receipt = other.join().unwrap();
        assert!(!receipt.accounting_unavailable && !other_receipt.accounting_unavailable);
        let flow = domain.observe_actual_flow().unwrap().unwrap();
        assert_eq!(flow.initial_credit_ns, 0);
        assert_eq!(flow.booked_reservation_ns, 0);
        assert_eq!(flow.unsettled_known_live_cpu_ns, 0);
        assert_eq!(flow.live_owners, 0);
        assert_eq!(flow.paid_cpu_debit_ns, flow.settled_full_cpu_ns);
        assert_eq!(
            flow.paid_cpu_debit_ns,
            receipt.total_cpu_ns.unwrap() + other_receipt.total_cpu_ns.unwrap()
        );
        assert!(flow.balance_identity_verified);
        println!(
            "{}",
            serde_json::json!({"schema":"history-writer-original-account-control-v1",
                "extra_w1_replays":replays,"before":before,"after":after,"settled":flow,
                "native_campaign_executed":false})
        );
    });
}

#[test]
fn history_writer_handoff_preserves_original_resource_and_deadline() {
    let (_directory, packet) = packet();
    for expire in [false, true] {
        let domain = ServiceMutationCpuDomain::cold_remote_history_epoch();
        let deadline = Instant::now() + Duration::from_secs(5);
        let operation = begin(&domain, deadline);
        qualify(&operation, &packet, deadline);
        consume_free_credit(&domain, &operation, &packet, deadline);
        let checks = AtomicUsize::new(0);
        let result = operation.checkpoint_handle().history_prepare_writer(&|| {
            assert_unlocked(&operation, &domain);
            if checks.fetch_add(1, Ordering::SeqCst) == 1 {
                if !expire {
                    return Err("PUBLIC_REQUEST_CANCELLED".into());
                }
                // The actual caller observation consumes its ORIGINAL end.
                // There is no replacement clock, shortened fixture deadline
                // or renewed lifetime inside the handoff implementation.
                while Instant::now() < deadline {
                    thread::sleep(deadline.saturating_duration_since(Instant::now()));
                }
            }
            Ok(())
        });
        assert_eq!(checks.load(Ordering::SeqCst), 2);
        assert_eq!(
            result.unwrap_err().to_string(),
            if expire {
                "PUBLIC_REQUEST_DEADLINE"
            } else {
                "PUBLIC_REQUEST_CANCELLED"
            }
        );
        assert_eq!(
            operation
                .live
                .state
                .lock()
                .unwrap()
                .public_request
                .as_ref()
                .unwrap()
                .deadline,
            deadline
        );
        let receipt = operation.finish();
        assert!(!receipt.accounting_unavailable);
        let flow = domain.observe_actual_flow().unwrap().unwrap();
        assert_eq!(flow.paid_cpu_debit_ns, receipt.total_cpu_ns.unwrap());
        assert_eq!(flow.booked_reservation_ns, 0);
        assert!(flow.balance_identity_verified);
    }
}

#[test]
fn history_writer_handoff_denies_wait_to_unqualified_and_replayed_work() {
    let (_directory, packet) = packet();
    for replay in [false, true] {
        let domain = ServiceMutationCpuDomain::cold_remote_history_epoch();
        let deadline = Instant::now() + Duration::from_secs(5);
        let prior_cpu = if replay {
            let original = begin(&domain, deadline);
            qualify(&original, &packet, deadline);
            assert!(original.live.state.lock().unwrap().verified_completion);
            let receipt = original.finish();
            assert!(!receipt.accounting_unavailable);
            receipt.total_cpu_ns.unwrap()
        } else {
            0
        };
        let operation = begin(&domain, deadline);
        if replay {
            qualify(&operation, &packet, deadline);
            assert_eq!(domain.budget.lock().unwrap().completion_replay_skips, 1);
        }
        assert!(!operation.live.state.lock().unwrap().verified_completion);
        consume_free_credit(&domain, &operation, &packet, deadline);
        let checks = AtomicUsize::new(0);
        // Negative stored free credit is not itself refusal: the original
        // sampler still grants this operation's purchased start allowance.
        // Nonpromoted/replayed work keeps that verdict but obtains no wait.
        operation
            .checkpoint_handle()
            .history_prepare_writer(&|| {
                assert_unlocked(&operation, &domain);
                checks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        assert!(!operation.live.state.lock().unwrap().refused);
        assert_eq!(domain.observe().unwrap().in_flight, 1);
        consume_unobserved_paid_balance(&domain, &packet, deadline);
        checks.store(0, Ordering::SeqCst);
        let error = operation
            .checkpoint_handle()
            .history_prepare_writer(&|| {
                assert_unlocked(&operation, &domain);
                checks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap_err();
        assert!(error.is(crate::ErrorCode::PublicMutationCpuBudget));
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        assert!(operation.live.state.lock().unwrap().refused);
        let receipt = operation.finish();
        assert!(!receipt.accounting_unavailable);
        let flow = domain.observe_actual_flow().unwrap().unwrap();
        assert_eq!(
            flow.paid_cpu_debit_ns,
            prior_cpu + receipt.total_cpu_ns.unwrap()
        );
        assert_eq!(flow.booked_reservation_ns, 0);
        assert_eq!(domain.budget.lock().unwrap().verified_completions, 0);
    }
}

#[test]
fn history_writer_handoff_never_revives_refused_or_unknown_operation() {
    let (_directory, packet) = packet();
    for unknown in [false, true] {
        let domain = ServiceMutationCpuDomain::cold_remote_history_epoch();
        let deadline = Instant::now() + Duration::from_secs(5);
        let operation = begin(&domain, deadline);
        qualify(&operation, &packet, deadline);
        if unknown {
            operation
                .live
                .fail_next_sample
                .store(true, Ordering::Release);
        } else {
            // Accumulate real unsampled W1 CPU beyond the original paid balance,
            // then let the original held checkpoint refuse and latch refusal.
            consume_unobserved_paid_balance(&domain, &packet, deadline);
            assert!(operation
                .history_checkpoint(true, &|| alive(deadline))
                .unwrap_err()
                .is(crate::ErrorCode::PublicMutationCpuBudget));
        }
        let checks = AtomicUsize::new(0);
        let error = operation
            .checkpoint_handle()
            .history_prepare_writer(&|| {
                assert_unlocked(&operation, &domain);
                checks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap_err();
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        assert_eq!(
            error.to_string(),
            if unknown {
                "PUBLIC_MUTATION_CPU_UNAVAILABLE"
            } else {
                "PUBLIC_MUTATION_CPU_BUDGET"
            }
        );
        let receipt = operation.finish();
        assert_eq!(receipt.accounting_unavailable, unknown);
        assert_eq!(domain.observe().unwrap().accounting_unavailable, unknown);
        if unknown {
            assert!(domain.observe_actual_flow().unwrap().is_none());
        } else {
            let flow = domain.observe_actual_flow().unwrap().unwrap();
            assert_eq!(flow.paid_cpu_debit_ns, receipt.total_cpu_ns.unwrap());
            assert!(flow.balance_identity_verified);
        }
    }
}

#[test]
fn history_writer_handoff_keeps_funded_unqualified_path_without_wait() {
    let domain = ServiceMutationCpuDomain::standalone();
    let deadline = Instant::now() + Duration::from_secs(5);
    let operation = begin(&domain, deadline);
    assert!(!operation.live.state.lock().unwrap().verified_completion);
    assert!(domain.observe().unwrap().stored_credit_ns > 0);
    let checks = AtomicUsize::new(0);
    operation
        .checkpoint_handle()
        .history_prepare_writer(&|| {
            assert_unlocked(&operation, &domain);
            checks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
    assert_eq!(checks.load(Ordering::SeqCst), 1);
    assert!(!operation.live.state.lock().unwrap().refused);
    let receipt = operation.finish();
    assert!(!receipt.accounting_unavailable);
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(flow.paid_cpu_debit_ns, receipt.total_cpu_ns.unwrap());
    assert_eq!(flow.booked_reservation_ns, 0);
}
