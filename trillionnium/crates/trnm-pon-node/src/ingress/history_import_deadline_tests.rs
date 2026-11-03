//! Ordinary local completion controls for the final deadline fences.
//! No invalid work, external traffic or old-version reproducer is exercised.
use super::*;

fn wait_until_expired(deadline: Instant) {
    // Keep one actual absolute deadline. Spurious/early wakeups cannot turn
    // the late-result assertion into a scheduler-dependent successful result.
    while Instant::now() < deadline {
        thread::sleep(deadline.saturating_duration_since(Instant::now()));
    }
}

#[test]
fn metered_expiry_preserves_native_errors_and_settles_the_original_account() {
    for native_error in [false, true] {
        let cpu = public_v3::ServiceMutationCpuDomain::standalone();
        let before = cpu.observe_actual_flow().unwrap().unwrap();
        let resource_calls = AtomicUsize::new(0);
        let control = Control {
            deadline: Instant::now() + Duration::from_millis(100),
            resource: &|| {
                resource_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        };
        let mut calls_before_completion = 0;
        let result: Result<u64> = metered(&cpu, &control, |_| {
            calls_before_completion = resource_calls.load(Ordering::SeqCst);
            wait_until_expired(control.deadline);
            if native_error {
                Err("PAGE_PARENT".into())
            } else {
                Ok(7)
            }
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            if native_error {
                "PAGE_PARENT"
            } else {
                "PUBLIC_REQUEST_DEADLINE"
            }
        );
        assert_eq!(
            resource_calls.load(Ordering::SeqCst),
            calls_before_completion,
            "the final time fence must not re-observe Host authority"
        );
        let observation = cpu.observe().unwrap();
        assert_eq!(observation.in_flight, 0);
        assert!(!observation.accounting_unavailable);
        let after = cpu.observe_actual_flow().unwrap().unwrap();
        assert_eq!(after.initial_credit_ns, before.initial_credit_ns);
        assert_eq!(after.booked_reservation_ns, 0);
        assert_eq!(after.unsettled_known_live_cpu_ns, 0);
        assert!(after.paid_cpu_debit_ns > before.paid_cpu_debit_ns);
        assert_eq!(after.paid_cpu_debit_ns, after.settled_full_cpu_ns);
        assert!(after.balance_identity_verified);
    }
}

#[test]
fn scope_expiry_preserves_cleanup_native_error_and_cold_reopen() {
    for native_error in [false, true] {
        let (directory, settings, mut node, _packet, _clock) = fixture();
        let cpu = public_v3::ServiceMutationCpuDomain::standalone();
        node.bind_public_service_cpu_domain(&cpu).unwrap();
        let before = node.read_active().unwrap();
        let control = Control {
            deadline: Instant::now() + Duration::from_millis(250),
            resource: &|| Ok(()),
        };
        let result: Result<u64> = scoped(&mut Owner::Exclusive(&mut node), &control, |_, _| {
            // A completed ordinary action can outlive its request while the
            // mandatory owner cleanup still has to remove the settled epoch.
            wait_until_expired(control.deadline);
            if native_error {
                Err("PAGE_PARENT".into())
            } else {
                Ok(7)
            }
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            if native_error {
                "PAGE_PARENT"
            } else {
                "PUBLIC_REQUEST_DEADLINE"
            }
        );
        assert!(cpu.accounting_available());
        assert_eq!(cpu.observe().unwrap().in_flight, 0);
        assert_eq!(node.read_active().unwrap(), before);
        drop(node);
        let mut reopened = Node::open(directory.path(), settings, 2).unwrap();
        assert_eq!(reopened.read_active().unwrap(), before);
        // A late result after a successful close must not accidentally invoke
        // EpochGuard::drop's unclean-account fence or retain a crash marker.
        let reopened_cpu = reopened.remote_history_cpu_domain().unwrap();
        assert!(reopened_cpu.accounting_available());
        assert_eq!(reopened_cpu.observe().unwrap().stored_credit_ns, 0);
    }
}

#[test]
fn late_admission_keeps_committed_identity_paid_cpu_and_exact_retry() {
    let (directory, settings, mut node, packet, _clock) = fixture();
    let cpu = public_v3::ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&cpu).unwrap();
    let before = node.read_active().unwrap();
    let owner = Mutex::new(node);
    let id = packet.id().unwrap();
    let end = Instant::now() + Duration::from_secs(5);
    let w1 = Arc::new(AtomicUsize::new(0));
    let admitted = Arc::new(AtomicUsize::new(0));
    let observed_w1 = w1.clone();
    let observed_admitted = admitted.clone();
    OBSERVER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |stage| {
            if stage == "w1" {
                observed_w1.fetch_add(1, Ordering::SeqCst);
            }
            if stage == "admitted" {
                observed_admitted.fetch_add(1, Ordering::SeqCst);
                // This existing local hook is after the real native COMMIT.
                // The packet is valid, and no final activation is requested.
                wait_until_expired(end);
            }
        }));
    });
    let result = admit_shared_packet(&owner, packet.clone(), end, &|| Ok(()), None);
    OBSERVER.with(|hook| *hook.borrow_mut() = None);
    assert_eq!(admitted.load(Ordering::SeqCst), 1);
    assert!(result
        .unwrap_err()
        .is(crate::ErrorCode::PublicRequestDeadline));
    let verified = w1.load(Ordering::SeqCst);
    assert!(verified > 0);
    {
        let node = owner.lock().unwrap();
        assert_eq!(
            node.packet(id).unwrap().encode().unwrap(),
            packet.encode().unwrap()
        );
        assert_eq!(node.read_active().unwrap(), before);
    }
    let paid = cpu.observe_actual_flow().unwrap().unwrap();
    assert!(paid.paid_cpu_debit_ns > 0);
    assert_eq!(paid.paid_cpu_debit_ns, paid.settled_full_cpu_ns);
    assert_eq!(paid.booked_reservation_ns, 0);
    assert_eq!(paid.unsettled_known_live_cpu_ns, 0);
    assert!(paid.balance_identity_verified);
    assert_eq!(cpu.observe().unwrap().in_flight, 0);
    assert!(cpu.accounting_available());
    assert_eq!(cpu.observe_completion_work().unwrap().retained_identities, 1);

    let observed_w1 = w1.clone();
    OBSERVER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |stage| {
            if stage == "w1" {
                observed_w1.fetch_add(1, Ordering::SeqCst);
            }
        }));
    });
    let retry = admit_shared_packet(
        &owner,
        packet.clone(),
        Instant::now() + Duration::from_secs(10),
        &|| Ok(()),
        Some(id),
    );
    OBSERVER.with(|hook| *hook.borrow_mut() = None);
    assert_eq!(retry.unwrap(), (false, Some(id)));
    assert_eq!(w1.load(Ordering::SeqCst), verified);
    assert_eq!(cpu.observe_completion_work().unwrap().retained_identities, 1);
    let after_retry = cpu.observe_actual_flow().unwrap().unwrap();
    assert!(after_retry.paid_cpu_debit_ns >= paid.paid_cpu_debit_ns);
    assert_eq!(after_retry.initial_credit_ns, paid.initial_credit_ns);
    assert_eq!(after_retry.booked_reservation_ns, 0);
    assert_eq!(after_retry.unsettled_known_live_cpu_ns, 0);
    drop(owner);

    let reopened = Node::open(directory.path(), settings, 2).unwrap();
    assert_eq!(
        reopened.packet(id).unwrap().encode().unwrap(),
        packet.encode().unwrap()
    );
    assert_eq!(reopened.read_active().unwrap().0, id);
}
