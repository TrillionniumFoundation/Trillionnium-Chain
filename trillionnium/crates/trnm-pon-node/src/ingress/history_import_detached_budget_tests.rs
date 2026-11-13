//! Scope regression for the original cold History CPU account. The existing
//! test-only hook performs extra real W1 arithmetic to reach actual debt;
//! it is not useful application work or a throughput/campaign measurement.
//! The original M06 cut remains a pre-completion refusal control. Positive
//! continuation starts only after the actual native commit has qualified its
//! original operation, with its writer released and its deadline unchanged.
use super::*;
use public_v3::request_observation::ThreadCpuStamp;
use rusqlite::OptionalExtension;
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

#[derive(Clone, Copy, Debug)]
enum QualificationCut {
    BeforeNativeCompletion,
    NativeCommitted,
}

fn detached_history_original_account(mode: DuringRefill, qualification: QualificationCut) {
    let (directory, settings, node, packet, clock) = fixture();
    let native_complete = matches!(qualification, QualificationCut::NativeCommitted);
    let successor =
        native_complete.then(|| history_successor(directory.path(), &settings, &packet, clock));
    let id = packet.id().unwrap();
    let tip = successor.as_ref().map_or(id, |packet| packet.id().unwrap());
    let mut import = page(&settings, &packet);
    if let Some(successor) = &successor {
        import
            .packets
            .push(hex::encode(successor.encode().unwrap()));
        import.tip = hex::encode(tip);
        import.next = hex::encode(tip);
    }
    let owner = Arc::new(Mutex::new(node));
    let original = owner.lock().unwrap().remote_history_cpu_domain().unwrap();
    assert_eq!(original.observe().unwrap().stored_credit_ns, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    let replay = Arc::new(Mutex::new(None));
    let before_epoch_close = Arc::new(Mutex::new(None));
    let injected = Arc::new(AtomicBool::new(false));
    let observed_owner = owner.clone();
    let observed_domain = original.clone();
    let observed_packet = packet.clone();
    let observed_replay = replay.clone();
    let observed_close = before_epoch_close.clone();
    let observed_injected = injected.clone();
    OBSERVER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |stage| {
            let selected = if native_complete { "admitted" } else { "m06" };
            if stage == selected && !observed_injected.swap(true, Ordering::SeqCst) {
                // Establish the actual detached scope before adding the local
                // test workload. The production owner and account stay intact.
                observed_owner.try_lock().unwrap().active().unwrap();
                assert_eq!(
                    observed_domain
                        .observe_completion_work()
                        .unwrap()
                        .live_completions,
                    usize::from(native_complete)
                );
                *observed_replay.lock().unwrap() = Some(consume_original_credit(
                    &observed_domain,
                    &observed_packet,
                    deadline,
                ));
            }
            if stage == "before_epoch_close" {
                // Both observations are read-only and occur after settlement.
                // Do not refill, extend the request, repair debt or bypass the
                // last-epoch crash fence merely to obtain diagnostic evidence.
                *observed_close.lock().unwrap() = Some((
                    observed_domain.observe().unwrap(),
                    observed_domain.observe_actual_flow().unwrap(),
                ));
            }
        }));
    });
    let refill_checks = AtomicUsize::new(0);
    let first_refill_credit = Mutex::new(None);
    let resource = || {
        let balance = original.observe()?;
        if balance.stored_credit_ns < -i128::from(balance.start_reserve_ns) {
            refill_checks.fetch_add(1, Ordering::SeqCst);
            let mut first = first_refill_credit.lock().unwrap();
            if first.is_none() {
                *first = Some(original.observe_actual_flow()?.unwrap().credited_refill_ns);
            }
            drop(first);
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
    let observation = HistoryImportObserver::new();
    let result = receive_observed(
        Owner::Shared(&owner),
        import,
        tip,
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
    let before_epoch_close = before_epoch_close.lock().unwrap().take();
    let after_cpu = original.observe().unwrap();
    let flow = original.observe_actual_flow().unwrap();
    let db = rusqlite::Connection::open_with_flags(
        directory.path().join("native.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let epoch_marker: Option<Vec<u8>> = db
        .query_row(
            "SELECT value FROM metadata WHERE key='ordinary-public-v3-epoch-v1'",
            [],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    drop(db);
    println!(
        "{}",
        serde_json::json!({
            "schema": "history-detached-native-completion-control-v3",
            "mode": format!("{mode:?}"),
            "qualification": format!("{qualification:?}"),
            "outcome": result.as_ref().map(hex::encode).map_err(ToString::to_string),
            "replay": *replay.lock().unwrap(),
            "refill_resource_checks": refill_checks.load(Ordering::SeqCst),
            "first_refill_credited_ns": *first_refill_credit.lock().unwrap(),
            "before_epoch_close": before_epoch_close.as_ref().map(|(cpu, flow)| {
                serde_json::json!({"cpu":cpu,"flow":flow})
            }),
            "after_epoch_close_cpu": after_cpu,
            "epoch_marker": epoch_marker.as_ref().map(hex::encode),
            "flow": flow,
            "history": snapshot,
            "native_campaign_executed": false,
        })
    );
    assert!(injected.load(Ordering::SeqCst));
    let (before_cpu, before_flow) =
        before_epoch_close.expect("settled pre-close cut was not reached");
    let before_flow = before_flow.expect("original settled CPU identity is unavailable");
    assert!(!before_cpu.accounting_unavailable);
    assert_eq!(before_cpu.in_flight, 0);
    assert_eq!(before_flow.initial_credit_ns, 0);
    assert_eq!(before_flow.booked_reservation_ns, 0);
    assert_eq!(before_flow.termination_reserved_ns, 0);
    assert_eq!(before_flow.unsettled_known_live_cpu_ns, 0);
    assert_eq!(before_flow.live_owners, 0);
    assert_eq!(
        before_flow.paid_cpu_debit_ns,
        before_flow.settled_full_cpu_ns
    );
    assert!(before_flow.balance_identity_verified);
    assert_eq!(before_flow.stored_credit_ns, before_cpu.stored_credit_ns);
    assert!(
        before_flow.paid_cpu_debit_ns
            >= replay
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .actual_thread_cpu_ns
    );
    assert_eq!(after_cpu.stored_credit_ns, before_cpu.stored_credit_ns);
    assert_eq!(after_cpu.in_flight, 0);
    let close = snapshot
        .phases
        .iter()
        .find(|phase| phase.phase == SubmitPhase::HistoryEpochClose)
        .unwrap();
    let dirty_close = before_cpu.stored_credit_ns < 0;
    assert!(close.started && close.completed);
    if dirty_close {
        // Known settled debt is deliberately fenced at the last epoch close.
        // Its later optional flow is unavailable because the ORIGINAL crash
        // guard latched unavailable, not because the debit identity was lost.
        assert_eq!(close.accepted, Some(false));
        assert_eq!(close.error_code, Some("PUBLIC_MUTATION_CPU_UNAVAILABLE"));
        assert!(after_cpu.accounting_unavailable);
        assert!(flow.is_none());
        assert_eq!(epoch_marker.as_deref(), Some(b"active-v1".as_slice()));
        assert!(result
            .as_ref()
            .err()
            .unwrap()
            .is(crate::ErrorCode::PublicMutationCpuUnavailable));
    } else {
        assert_eq!(close.accepted, Some(true));
        assert_eq!(close.error_code, None);
        assert!(!after_cpu.accounting_unavailable);
        assert_eq!(flow.as_ref(), Some(&before_flow));
        assert!(epoch_marker.is_none());
    }
    if native_complete {
        assert!(
            refill_checks.load(Ordering::SeqCst) > 0,
            "complete native continuation missed its original refill control: {result:?}"
        );
    } else {
        assert_eq!(refill_checks.load(Ordering::SeqCst), 0);
        assert!(first_refill_credit.lock().unwrap().is_none());
    }
    assert_eq!(original.observe().unwrap().in_flight, 0);
    let node = owner.lock().unwrap();
    assert!(node
        .public_service_cpu_domain()
        .unwrap()
        .shares_domain_with(&original));
    let first_packet = &snapshot.packets[0];
    match (qualification, mode) {
        (QualificationCut::BeforeNativeCompletion, _) => {
            assert!(result.is_err());
            assert!(first_packet.phases.iter().any(|phase| {
                phase.phase == SubmitPhase::Execution
                    && phase.error_code == Some("PUBLIC_MUTATION_CPU_BUDGET")
            }));
            assert!(first_packet
                .phases
                .iter()
                .filter(|phase| phase.phase == SubmitPhase::Commit)
                .all(|phase| !phase.started));
            assert_eq!(node.read_active().unwrap().0, settings.genesis());
            assert!(node.packet(id).is_err());
            assert_eq!(
                original
                    .observe_completion_work()
                    .unwrap()
                    .retained_identities,
                0
            );
        }
        (QualificationCut::NativeCommitted, DuringRefill::Continue) => {
            assert_eq!(result.unwrap(), tip);
            assert_eq!(node.read_active().unwrap().0, tip);
            assert_eq!(
                node.packet(id).unwrap().encode().unwrap(),
                packet.encode().unwrap()
            );
            assert_eq!(
                node.packet(tip).unwrap().encode().unwrap(),
                successor.as_ref().unwrap().encode().unwrap()
            );
            let completion = original.observe_completion_work().unwrap();
            assert_eq!(completion.retained_identities, 2);
            assert_eq!(completion.live_completions, 0);
            let flow = flow.unwrap();
            assert!(flow.credited_refill_ns > first_refill_credit.lock().unwrap().unwrap());
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
        (QualificationCut::NativeCommitted, DuringRefill::Cancel | DuringRefill::Expire) => {
            let expected = match mode {
                DuringRefill::Cancel => "PUBLIC_REQUEST_CANCELLED",
                DuringRefill::Expire => "PUBLIC_REQUEST_DEADLINE",
                DuringRefill::Continue => unreachable!(),
            };
            assert!(result.is_err());
            assert!(
                first_packet.phases.iter().any(|phase| {
                    phase.phase == SubmitPhase::SubmitResult && phase.error_code == Some(expected)
                }),
                "original detached cancellation was not preserved: {snapshot:?}"
            );
            assert!(first_packet
                .phases
                .iter()
                .any(|phase| phase.phase == SubmitPhase::Commit && phase.accepted == Some(true)));
            assert_eq!(node.read_active().unwrap().0, settings.genesis());
            assert_eq!(
                node.packet(id).unwrap().encode().unwrap(),
                packet.encode().unwrap()
            );
            assert!(node.packet(tip).is_err());
            assert!(snapshot.packets[1]
                .phases
                .iter()
                .all(|phase| !phase.started));
            assert_eq!(
                original
                    .observe_completion_work()
                    .unwrap()
                    .retained_identities,
                1
            );
        }
    }
    drop(node);
    drop(owner);
    let mut reopened = Node::open(directory.path(), settings.clone(), 2).unwrap();
    assert_eq!(
        reopened.read_active().unwrap().0,
        if native_complete {
            // Ordinary cold recovery may activate already committed work; a
            // cancelled continuation never erases the first packet's commit.
            if matches!(mode, DuringRefill::Continue) {
                tip
            } else {
                id
            }
        } else {
            settings.genesis()
        }
    );
    if dirty_close {
        assert!(reopened
            .remote_history_cpu_domain()
            .err()
            .unwrap()
            .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
    }
}

#[test]
fn shared_detached_history_continues_from_real_deficit_without_new_credit() {
    detached_history_original_account(DuringRefill::Continue, QualificationCut::NativeCommitted);
}

#[test]
fn shared_detached_history_refill_keeps_original_resource_cancellation() {
    detached_history_original_account(DuringRefill::Cancel, QualificationCut::NativeCommitted);
}

#[test]
fn shared_detached_history_refill_cannot_renew_original_deadline() {
    detached_history_original_account(DuringRefill::Expire, QualificationCut::NativeCommitted);
}

#[test]
fn shared_detached_history_before_native_completion_keeps_sticky_budget_refusal() {
    detached_history_original_account(
        DuringRefill::Continue,
        QualificationCut::BeforeNativeCompletion,
    );
}
