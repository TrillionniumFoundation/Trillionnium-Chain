//! Scope regression for the original cold History CPU account. The existing
//! test-only M06 hook performs extra real W1 arithmetic to reach actual debt;
//! it is not useful application work or a throughput/campaign measurement.
use super::*;
use public_v3::request_observation::ThreadCpuStamp;
use std::sync::atomic::AtomicBool;

#[derive(Default, serde::Serialize)]
struct ReplayDepletion {
    completed_native_replays: u64,
    actual_thread_cpu_ns: u64,
    projected_paid_credit_ns: i128,
}

fn consume_original_credit(
    domain: &public_v3::ServiceMutationCpuDomain,
    packet: &Packet,
    deadline: Instant,
) -> ReplayDepletion {
    let mut evidence = ReplayDepletion::default();
    loop {
        assert!(
            Instant::now() < deadline,
            "actual CPU deficit fixture expired"
        );
        let stamp = ThreadCpuStamp::start().unwrap();
        WorkCheckedPacket::verify_with_progress(packet.clone(), &mut |_| {
            ensure(Instant::now() < deadline, "PUBLIC_REQUEST_DEADLINE")
        })
        .unwrap();
        evidence.completed_native_replays += 1;
        evidence.actual_thread_cpu_ns += stamp.finish().unwrap();
        // Read-only projection: no balance assignment, fabricated clock, new
        // reservation, policy increase or additional production checkpoint.
        evidence.projected_paid_credit_ns = domain
            .observe_credit_freshness()
            .unwrap()
            .unwrap()
            .projected_paid_credit_ns;
        if i128::from(evidence.actual_thread_cpu_ns)
            > evidence.projected_paid_credit_ns + 25_000_000
        {
            return evidence;
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum DuringRefill {
    Continue,
    Cancel,
    Expire,
}

fn detached_history_original_account(mode: DuringRefill) {
    let (directory, settings, node, packet, clock) = fixture();
    let owner = Arc::new(Mutex::new(node));
    let original = owner.lock().unwrap().remote_history_cpu_domain().unwrap();
    assert_eq!(original.observe().unwrap().stored_credit_ns, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    let replay = Arc::new(Mutex::new(None));
    let injected = Arc::new(AtomicBool::new(false));
    let observed_owner = owner.clone();
    let observed_domain = original.clone();
    let observed_packet = packet.clone();
    let observed_replay = replay.clone();
    let observed_injected = injected.clone();
    OBSERVER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |stage| {
            if stage == "m06" && !observed_injected.swap(true, Ordering::SeqCst) {
                // Establish the actual detached scope before adding the local
                // test workload. The production owner and account stay intact.
                observed_owner.try_lock().unwrap().active().unwrap();
                *observed_replay.lock().unwrap() = Some(consume_original_credit(
                    &observed_domain,
                    &observed_packet,
                    deadline,
                ));
            }
        }));
    });
    let refill_checks = AtomicUsize::new(0);
    let resource = || {
        let balance = original.observe()?;
        if balance.stored_credit_ns < -i128::from(balance.start_reserve_ns) {
            refill_checks.fetch_add(1, Ordering::SeqCst);
            // Waiting is legal here only because the actual Node writer is
            // released. Held preparation/commit/activation keep their refusal.
            owner.try_lock().unwrap().active().unwrap();
            match mode {
                DuringRefill::Continue => {}
                DuringRefill::Cancel => return Err("PUBLIC_REQUEST_CANCELLED".into()),
                DuringRefill::Expire => {
                    while Instant::now() < deadline {
                        thread::sleep(deadline.saturating_duration_since(Instant::now()));
                    }
                }
            }
        }
        Ok(())
    };
    let id = packet.id().unwrap();
    let observation = HistoryImportObserver::new();
    let result = receive_observed(
        Owner::Shared(&owner),
        page(&settings, &packet),
        id,
        settings.genesis(),
        clock,
        Control {
            deadline,
            resource: &resource,
        },
        Some(&observation),
    );
    OBSERVER.with(|hook| *hook.borrow_mut() = None);
    let snapshot = observation.snapshot();
    let flow = original.observe_actual_flow().unwrap();
    println!(
        "{}",
        serde_json::json!({
            "schema": "history-detached-original-refill-control-v1",
            "mode": format!("{mode:?}"),
            "outcome": result.as_ref().map(hex::encode).map_err(ToString::to_string),
            "replay": *replay.lock().unwrap(),
            "refill_resource_checks": refill_checks.load(Ordering::SeqCst),
            "flow": flow,
            "history": snapshot,
            "native_campaign_executed": false,
        })
    );
    assert!(injected.load(Ordering::SeqCst));
    assert!(
        refill_checks.load(Ordering::SeqCst) > 0,
        "detached execution refused actual debt before its original refill control: {result:?}"
    );
    assert_eq!(original.observe().unwrap().in_flight, 0);
    let node = owner.lock().unwrap();
    assert!(node
        .public_service_cpu_domain()
        .unwrap()
        .shares_domain_with(&original));
    match mode {
        DuringRefill::Continue => {
            assert_eq!(result.unwrap(), id);
            assert_eq!(node.read_active().unwrap().0, id);
            assert_eq!(
                node.packet(id).unwrap().encode().unwrap(),
                packet.encode().unwrap()
            );
            let flow = flow.unwrap();
            assert_eq!(flow.initial_credit_ns, 0);
            assert_eq!(flow.booked_reservation_ns, 0);
            assert_eq!(flow.unsettled_known_live_cpu_ns, 0);
            assert_eq!(flow.paid_cpu_debit_ns, flow.settled_full_cpu_ns);
            assert!(flow.balance_identity_verified);
            assert!(
                flow.paid_cpu_debit_ns
                    >= replay
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .actual_thread_cpu_ns
            );
        }
        DuringRefill::Cancel | DuringRefill::Expire => {
            let expected = match mode {
                DuringRefill::Cancel => "PUBLIC_REQUEST_CANCELLED",
                DuringRefill::Expire => "PUBLIC_REQUEST_DEADLINE",
                DuringRefill::Continue => unreachable!(),
            };
            assert!(result.is_err());
            let packet_record = &snapshot.packets[0];
            assert!(
                packet_record.phases.iter().any(|phase| {
                    phase.phase == SubmitPhase::Execution && phase.error_code == Some(expected)
                }),
                "original detached cancellation was not preserved: {snapshot:?}"
            );
            assert!(packet_record
                .phases
                .iter()
                .filter(|phase| phase.phase == SubmitPhase::Commit)
                .all(|phase| !phase.started));
            assert_eq!(node.read_active().unwrap().0, settings.genesis());
            assert!(node.packet(id).is_err());
        }
    }
    drop(node);
    drop(owner);
    let reopened = Node::open(directory.path(), settings.clone(), 2).unwrap();
    assert_eq!(
        reopened.read_active().unwrap().0,
        if matches!(mode, DuringRefill::Continue) {
            id
        } else {
            settings.genesis()
        }
    );
}

#[test]
fn shared_detached_history_continues_from_real_deficit_without_new_credit() {
    detached_history_original_account(DuringRefill::Continue);
}

#[test]
fn shared_detached_history_refill_keeps_original_resource_cancellation() {
    detached_history_original_account(DuringRefill::Cancel);
}

#[test]
fn shared_detached_history_refill_cannot_renew_original_deadline() {
    detached_history_original_account(DuringRefill::Expire);
}
