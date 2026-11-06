use super::super::{
    DevelopmentIdentity, Hello, PublicPolicy, PublicServer, ServiceMutationCpuDomain, Settings,
    MAX_MUTATING_GRANTS, MAX_PAID_BODY_BYTES, MAX_READ_GRANTS, READ_BODY_RESERVE,
};
use super::*;

struct Held {
    lease: ConnectionLease,
    _slot: BufferPermit,
    cancelled: Arc<AtomicBool>,
}
fn connection(intake: &ListenerIntake, now: Instant) -> Held {
    let slot = BufferPermit::acquire(intake.connections.clone(), 1, MAX_CONNECTIONS).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let lease = intake
        .connection_lease(&slot, cancelled.clone(), now)
        .unwrap();
    Held {
        lease,
        _slot: slot,
        cancelled,
    }
}
fn ready(
    held: &Held,
    kind: PendingKind,
    op: u8,
    stop: &Arc<AtomicBool>,
    now: Instant,
    deadline: Instant,
) -> PendingOrder {
    held.lease.protect().unwrap();
    held.lease
        .register_ready(kind, op, deadline, stop, now)
        .unwrap()
}
fn grant(
    intake: &ListenerIntake,
    held: &Held,
    op: u8,
    stop: &Arc<AtomicBool>,
    now: Instant,
    deadline: Instant,
) -> PendingOrder {
    let challenge = ready(held, PendingKind::Challenge, op, stop, now, deadline);
    assert!(intake
        .try_ready_challenge(&held.lease, challenge, op, now)
        .unwrap());
    // This fixture exercises the private scheduling boundary. Real Solution
    // cryptography and spent-cookie ordering are covered by socket tests.
    ready(held, PendingKind::Grant, op, stop, now, deadline)
}
fn server(domain: &ServiceMutationCpuDomain, key: u8) -> PublicServer {
    PublicServer::with_continuous_domain(
        DevelopmentIdentity::from_secret_hex(&hex::encode([key; 32])).unwrap(),
        PublicPolicy::new(8, Duration::from_secs(2)).unwrap(),
        domain,
    )
    .unwrap()
}
fn cookie(op: u8, len: usize) -> Cookie {
    server(&ServiceMutationCpuDomain::standalone(), 71)
        .cookie(
            &Settings::development(Some(1)).unwrap(),
            Hello {
                op,
                len,
                caller: [2; 32],
                digest: [3; 32],
                client_nonce: [4; 32],
            },
            "127.0.0.1:1".parse().unwrap(),
        )
        .unwrap()
}

#[test]
fn shared_readiness_reversed_listener_polling_and_partial_inputs_keep_fifo() {
    let domain = ServiceMutationCpuDomain::standalone();
    let a = server(&domain, 71).listener_intake().unwrap();
    let b = server(&domain, 72).listener_intake().unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    let now = Instant::now();
    let deadline = now + Duration::from_secs(2);
    let stop = Arc::new(AtomicBool::new(false));
    let partial = connection(&a, now);
    let older = connection(&a, now);
    let newer = connection(&b, now);
    assert!(partial
        .lease
        .register_ready(PendingKind::Challenge, 1, deadline, &stop, now)
        .is_err());
    let first = ready(&older, PendingKind::Challenge, 1, &stop, now, deadline);
    let second = ready(&newer, PendingKind::Challenge, 1, &stop, now, deadline);
    assert!(first.sequence < second.sequence);
    let tokens = a.challenges.lock().unwrap().tokens;
    // Force the later listener to poll first; no scheduling luck is involved.
    for _ in 0..64 {
        assert!(!b.try_ready_challenge(&newer.lease, second, 1, now).unwrap());
        assert_eq!(a.challenges.lock().unwrap().tokens, tokens);
    }
    assert!(a.try_ready_challenge(&older.lease, first, 1, now).unwrap());
    let third = ready(&partial, PendingKind::Challenge, 1, &stop, now, deadline);
    assert!(!a
        .try_ready_challenge(&partial.lease, third, 1, now)
        .unwrap());
    assert!(b.try_ready_challenge(&newer.lease, second, 1, now).unwrap());
    assert!(a
        .try_ready_challenge(&partial.lease, third, 1, now)
        .unwrap());
    assert_eq!(a.challenges.lock().unwrap().tokens, tokens - 3);
    assert_eq!(*a.connections.lock().unwrap(), 3);
    assert_eq!(*a.body_pool.lock().unwrap(), 0);
}

#[test]
fn shared_readiness_nonhead_polling_does_not_scan_or_renew_order() {
    let intake = ListenerIntake::new();
    let now = Instant::now();
    let deadline = now + Duration::from_secs(2);
    let stop = Arc::new(AtomicBool::new(false));
    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let request = connection(&intake, now);
        let order = ready(&request, PendingKind::Challenge, 2, &stop, now, deadline);
        held.push((request, order));
    }
    let scans = intake.leases.lock().unwrap().head_scans;
    for _ in 0..64 {
        for (request, order) in &held[1..] {
            assert!(!intake
                .try_ready_challenge(&request.lease, *order, 2, now)
                .unwrap());
            assert_eq!(
                request
                    .lease
                    .register_ready(
                        PendingKind::Challenge,
                        2,
                        deadline,
                        &stop,
                        now + Duration::from_millis(1)
                    )
                    .unwrap(),
                *order
            );
        }
    }
    let registry = intake.leases.lock().unwrap();
    assert_eq!(registry.entries.len(), MAX_CONNECTIONS);
    assert_eq!(registry.next_pending, MAX_CONNECTIONS as u64);
    assert_eq!(
        registry.head_scans, scans,
        "stable non-head polls rescanned the registry"
    );
    drop(registry);
    assert!(held
        .iter()
        .all(|(_, order)| order.entered_at == now && order.deadline == deadline));
    drop(held);
    assert_eq!(*intake.connections.lock().unwrap(), 0);
    assert!(intake.leases.lock().unwrap().entries.is_empty());
    assert_eq!(
        intake.leases.lock().unwrap().next_pending,
        MAX_CONNECTIONS as u64
    );
}

#[test]
fn shared_readiness_other_listener_retires_expired_cancelled_and_stopped_heads() {
    for reason in ["deadline", "cancelled", "stopped"] {
        let intake = ListenerIntake::new();
        let now = Instant::now();
        let first_stop = Arc::new(AtomicBool::new(false));
        let other_stop = Arc::new(AtomicBool::new(false));
        let first = connection(&intake, now);
        let second = connection(&intake, now);
        let old = ready(
            &first,
            PendingKind::Challenge,
            1,
            &first_stop,
            now,
            now + Duration::from_millis(1),
        );
        let next = ready(
            &second,
            PendingKind::Challenge,
            1,
            &other_stop,
            now,
            now + Duration::from_secs(2),
        );
        let poll = match reason {
            "deadline" => old.deadline,
            "cancelled" => {
                first.cancelled.store(true, Ordering::Release);
                now
            }
            _ => {
                first_stop.store(true, Ordering::Release);
                now
            }
        };
        // The old listener does not run again and still owns its Connection.
        assert!(
            intake
                .try_ready_challenge(&second.lease, next, 1, poll)
                .unwrap(),
            "{reason}"
        );
        assert_eq!(
            *intake.connections.lock().unwrap(),
            2,
            "retiring order refunded a socket"
        );
        assert_eq!(intake.leases.lock().unwrap().entries.len(), 2);
        assert!(intake.leases.lock().unwrap().entries[&first.lease.id]
            .ready
            .is_none());
        assert!(first
            .lease
            .register_ready(
                PendingKind::Challenge,
                1,
                now + Duration::from_secs(4),
                &first_stop,
                now
            )
            .is_err());
        assert!(
            intake
                .try_ready_challenge(&first.lease, old, 1, now)
                .is_err(),
            "stale clock revived {reason}"
        );
        drop((first, second));
        assert_eq!(*intake.connections.lock().unwrap(), 0);
    }
}

#[test]
fn shared_readiness_drop_head_and_new_arrival_cannot_overtake_existing_waiter() {
    let intake = ListenerIntake::new();
    let now = Instant::now();
    let end = now + Duration::from_secs(2);
    let stop = Arc::new(AtomicBool::new(false));
    let a = connection(&intake, now);
    let b = connection(&intake, now);
    let _first = ready(&a, PendingKind::Challenge, 1, &stop, now, end);
    let second = ready(&b, PendingKind::Challenge, 1, &stop, now, end);
    drop(a);
    let c = connection(&intake, now);
    let third = ready(&c, PendingKind::Challenge, 1, &stop, now, end);
    assert!(!intake.try_ready_challenge(&c.lease, third, 1, now).unwrap());
    assert!(intake
        .try_ready_challenge(&b.lease, second, 1, now)
        .unwrap());
    assert!(intake.try_ready_challenge(&c.lease, third, 1, now).unwrap());
    assert_eq!(intake.leases.lock().unwrap().next_pending, 3);
}

#[test]
fn shared_readiness_preserves_read_challenge_reserve_under_mutation_pressure() {
    let intake = ListenerIntake::new();
    let now = intake.challenges.lock().unwrap().updated;
    let deadline = now + Duration::from_secs(2);
    let stop = Arc::new(AtomicBool::new(false));
    for _ in 0..CHALLENGE_BURST - READ_CHALLENGE_RESERVE {
        assert!(intake.try_challenge(1, now).unwrap());
    }
    let mutation = connection(&intake, now);
    let mutation_order = ready(&mutation, PendingKind::Challenge, 1, &stop, now, deadline);
    for _ in 0..READ_CHALLENGE_RESERVE {
        assert!(!intake
            .try_ready_challenge(&mutation.lease, mutation_order, 1, now)
            .unwrap());
        let read = connection(&intake, now);
        let order = ready(&read, PendingKind::Challenge, 2, &stop, now, deadline);
        assert!(intake
            .try_ready_challenge(&read.lease, order, 2, now)
            .unwrap());
    }
    assert_eq!(intake.challenges.lock().unwrap().tokens, 0);
    assert_eq!(
        intake.leases.lock().unwrap().entries[&mutation.lease.id]
            .ready
            .as_ref()
            .unwrap()
            .order,
        mutation_order
    );
    assert_eq!(*intake.body_pool.lock().unwrap(), 0);
}

#[test]
fn shared_readiness_grants_are_fifo_with_atomic_body_rollback_and_read_reserve() {
    let intake = ListenerIntake::new();
    let now = Instant::now();
    let end = now + Duration::from_secs(2);
    let stop = Arc::new(AtomicBool::new(false));
    let first = connection(&intake, now);
    let second = connection(&intake, now);
    let read = connection(&intake, now);
    let a = grant(&intake, &first, 1, &stop, now, end);
    let b = grant(&intake, &second, 1, &stop, now, end);
    let r = grant(&intake, &read, 2, &stop, now, end);
    let bulk = BufferPermit::acquire(
        intake.body_pool.clone(),
        MAX_PAID_BODY_BYTES - READ_BODY_RESERVE,
        MAX_PAID_BODY_BYTES,
    )
    .unwrap();
    let mutation_cookie = cookie(1, 2);
    for _ in 0..64 {
        assert!(intake
            .try_ready_paid_permits(&first.lease, a, &mutation_cookie, now)
            .unwrap()
            .is_none());
        assert!(intake
            .try_ready_paid_permits(&second.lease, b, &mutation_cookie, now)
            .unwrap()
            .is_none());
        assert_eq!(*intake.mutating_grants.lock().unwrap(), 0);
    }
    let read_permits = intake
        .try_ready_paid_permits(&read.lease, r, &cookie(2, 1), now)
        .unwrap()
        .unwrap();
    assert_eq!(*intake.read_grants.lock().unwrap(), 1);
    assert_eq!(
        *intake.body_pool.lock().unwrap(),
        MAX_PAID_BODY_BYTES - READ_BODY_RESERVE + 3
    );
    drop(bulk);
    assert!(intake
        .try_ready_paid_permits(&second.lease, b, &mutation_cookie, now)
        .unwrap()
        .is_none());
    let first_permits = intake
        .try_ready_paid_permits(&first.lease, a, &mutation_cookie, now)
        .unwrap()
        .unwrap();
    let second_permits = intake
        .try_ready_paid_permits(&second.lease, b, &mutation_cookie, now)
        .unwrap()
        .unwrap();
    assert_eq!(*intake.mutating_grants.lock().unwrap(), 2);
    assert_eq!(*intake.body_pool.lock().unwrap(), 15);
    drop((first_permits, second_permits, read_permits));
    assert_eq!(*intake.mutating_grants.lock().unwrap(), 0);
    assert_eq!(*intake.read_grants.lock().unwrap(), 0);
    assert_eq!(*intake.body_pool.lock().unwrap(), 0);
    assert_eq!((MAX_MUTATING_GRANTS, MAX_READ_GRANTS), (8, 8));
}

#[test]
fn shared_readiness_rejects_wrong_domain_token_phase_operation_and_renewal() {
    let intake = ListenerIntake::new();
    let other = ListenerIntake::new();
    let now = Instant::now();
    let end = now + Duration::from_secs(2);
    let stop = Arc::new(AtomicBool::new(false));
    let held = connection(&intake, now);
    held.lease.protect().unwrap();
    assert!(held
        .lease
        .register_ready(PendingKind::Grant, 1, end, &stop, now)
        .is_err());
    let order = ready(&held, PendingKind::Challenge, 1, &stop, now, end);
    let tokens = intake.challenges.lock().unwrap().tokens;
    assert!(other
        .try_ready_challenge(&held.lease, order, 1, now)
        .is_err());
    assert!(intake
        .try_ready_challenge(&held.lease, order, 2, now)
        .is_err());
    for changed in [
        PendingOrder {
            sequence: order.sequence + 1,
            ..order
        },
        PendingOrder {
            deadline: end + Duration::from_secs(1),
            ..order
        },
        PendingOrder {
            entered_at: now + Duration::from_nanos(1),
            ..order
        },
    ] {
        assert!(intake
            .try_ready_challenge(&held.lease, changed, 1, now)
            .is_err());
    }
    assert!(held
        .lease
        .register_ready(
            PendingKind::Challenge,
            1,
            end + Duration::from_secs(1),
            &stop,
            now
        )
        .is_err());
    assert!(held
        .lease
        .register_ready(
            PendingKind::Challenge,
            1,
            end,
            &Arc::new(AtomicBool::new(false)),
            now
        )
        .is_err());
    assert!(intake
        .try_ready_paid_permits(&held.lease, order, &cookie(1, 1), now)
        .is_err());
    assert_eq!(intake.challenges.lock().unwrap().tokens, tokens);
    assert_eq!(intake.leases.lock().unwrap().next_pending, 1);
    assert!(intake
        .try_ready_challenge(&held.lease, order, 1, now)
        .unwrap());
    assert!(intake
        .try_ready_challenge(&held.lease, order, 1, now)
        .is_err());
    assert!(held
        .lease
        .register_ready(PendingKind::Challenge, 1, end, &stop, now)
        .is_err());
    assert!(held
        .lease
        .register_ready(PendingKind::Grant, 2, end, &stop, now)
        .is_err());
    assert_eq!(*intake.body_pool.lock().unwrap(), 0);
}

#[test]
fn shared_readiness_sequence_exhaustion_does_not_revoke_or_renumber_existing_work() {
    let intake = ListenerIntake::new();
    let now = Instant::now();
    let end = now + Duration::from_secs(2);
    let stop = Arc::new(AtomicBool::new(false));
    let first = connection(&intake, now);
    let second = connection(&intake, now);
    intake.leases.lock().unwrap().next_pending = u64::MAX - 1;
    let order = ready(&first, PendingKind::Challenge, 1, &stop, now, end);
    assert_eq!(order.sequence, u64::MAX);
    second.lease.protect().unwrap();
    assert_eq!(
        second
            .lease
            .register_ready(PendingKind::Challenge, 1, end, &stop, now)
            .unwrap_err()
            .to_string(),
        "PUBLIC_PENDING_ORDER"
    );
    assert_eq!(
        first
            .lease
            .register_ready(PendingKind::Challenge, 1, end, &stop, now)
            .unwrap(),
        order
    );
    assert!(intake
        .try_ready_challenge(&first.lease, order, 1, now)
        .unwrap());
    assert!(intake.leases.lock().unwrap().entries[&second.lease.id]
        .ready
        .is_none());
    drop((first, second));
    let fresh = connection(&intake, now);
    fresh.lease.protect().unwrap();
    assert!(fresh
        .lease
        .register_ready(PendingKind::Challenge, 1, end, &stop, now)
        .is_err());
    assert_eq!(intake.leases.lock().unwrap().next_pending, u64::MAX);
}

#[test]
fn shared_readiness_registry_and_reservation_poison_fail_closed() {
    for registry_poison in [true, false] {
        let intake = Arc::new(ListenerIntake::new());
        let now = Instant::now();
        let end = now + Duration::from_secs(2);
        let stop = Arc::new(AtomicBool::new(false));
        let held = connection(&intake, now);
        let order = ready(&held, PendingKind::Challenge, 1, &stop, now, end);
        let shared = intake.clone();
        assert!(std::thread::spawn(move || {
            if registry_poison {
                let _guard = shared.leases.lock().unwrap();
                panic!("controlled shared-readiness registry poison");
            } else {
                let _guard = shared.challenges.lock().unwrap();
                panic!("controlled shared-readiness reservation poison");
            }
        })
        .join()
        .is_err());
        assert_eq!(
            intake
                .try_ready_challenge(&held.lease, order, 1, now)
                .unwrap_err()
                .to_string(),
            "PUBLIC_INTAKE_UNAVAILABLE"
        );
        if !registry_poison {
            assert!(intake.leases.lock().unwrap().entries[&held.lease.id]
                .ready
                .is_some());
        }
        assert_eq!(*intake.body_pool.lock().unwrap(), 0);
        assert_eq!(*intake.mutating_grants.lock().unwrap(), 0);
        drop(held);
        assert_eq!(*intake.connections.lock().unwrap(), 0);
    }
}
