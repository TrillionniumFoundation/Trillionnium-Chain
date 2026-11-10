use super::super::{begin_cpu, begin_cpu_observed, Control, HistoryImportObserver};
use super::*;
use std::sync::atomic::AtomicUsize;

#[test]
fn unentered_attribution_is_absent_and_retained_packet_shape_is_unchanged() {
    let observer = HistoryImportObserver::new();
    let empty = serde_json::to_value(observer.snapshot()).unwrap();
    assert!(empty.get("native_attribution").is_none());
    assert_eq!(empty["phases"].as_array().unwrap().len(), 19);
    observer.decoded_packet(0, [7; 32]);
    let recorded = serde_json::to_value(observer.snapshot()).unwrap();
    let packet = recorded["packets"][0].as_object().unwrap();
    assert_eq!(packet.len(), 3);
    for key in ["packet_index", "packet_id", "phases"] {
        assert!(packet.contains_key(key));
    }
    assert!(recorded.get("native_attribution").is_none());
}

#[test]
fn epoch_substeps_keep_original_result_and_do_not_invent_unentered_work() {
    let recorder = NativeAttribution::new(Instant::now());
    recorder.owner("exclusive");
    let calls = AtomicUsize::new(0);
    let result = observe_epoch(Some(&recorder), HistoryEpochSubstep::DomainLookup, || {
        calls.fetch_add(1, Ordering::Relaxed);
        Err::<(), _>("OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH".into())
    });
    assert_eq!(
        result.unwrap_err().to_string(),
        "OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH"
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let (snapshot, failures) = recorder.snapshot();
    let snapshot = snapshot.unwrap();
    assert_eq!(failures, 0);
    assert_eq!(snapshot.owner_mode, Some("exclusive"));
    assert_eq!(snapshot.epoch_substeps.len(), 1);
    let stage = snapshot.epoch_substeps[0];
    assert!(matches!(stage.substep, HistoryEpochSubstep::DomainLookup));
    assert_eq!(stage.span.accepted, Some(false));
    assert!(stage.span.completed && !stage.span.unwound);
    assert!(stage.span.wall_ns.is_some());
    assert!(snapshot.cpu_waits.is_empty());
}

#[test]
fn epoch_unwind_and_capture_contention_cannot_turn_into_success() {
    let recorder = NativeAttribution::new(Instant::now());
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<()> =
            observe_epoch(Some(&recorder), HistoryEpochSubstep::DurableBegin, || {
                panic!("original native epoch action panicked");
            });
    }));
    assert!(panicked.is_err());
    let row = recorder.snapshot().0.unwrap().epoch_substeps[0];
    assert!(row.span.unwound && !row.span.completed);
    assert_eq!(row.span.accepted, None);
    let lock = recorder.slots.lock().unwrap();
    let result = observe_epoch(Some(&recorder), HistoryEpochSubstep::DomainLookup, || {
        Err::<(), _>("PUBLIC_REQUEST_CANCELLED".into())
    });
    drop(lock);
    assert!(result
        .unwrap_err()
        .is(crate::ErrorCode::PublicRequestCancelled));
    assert_eq!(recorder.snapshot().1, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn actual_immediate_reservation_keeps_original_account_and_no_sleep_claim() {
    use super::super::public_v3::ServiceMutationCpuDomain;
    for observed in [false, true] {
        let domain = ServiceMutationCpuDomain::standalone();
        let recorder = NativeAttribution::new(Instant::now());
        let calls = AtomicUsize::new(0);
        let resource = || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        };
        let control = Control {
            deadline: Instant::now() + Duration::from_secs(2),
            resource: &resource,
        };
        let operation = if observed {
            begin_cpu_observed(&domain, &control, Some(&recorder))
        } else {
            begin_cpu(&domain, &control)
        }
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(domain.observe().unwrap().in_flight, 1);
        let settlement = operation.finish();
        assert!(!settlement.accounting_unavailable);
        assert_eq!(domain.observe().unwrap().in_flight, 0);
        assert!(
            domain
                .observe_actual_flow()
                .unwrap()
                .unwrap()
                .balance_identity_verified
        );
        let (snapshot, failures) = recorder.snapshot();
        assert_eq!(failures, 0);
        if observed {
            let row = snapshot.unwrap().cpu_waits[0];
            assert_eq!(
                (
                    row.reserve_attempts,
                    row.reserve_returns,
                    row.reserve_granted
                ),
                (1, 1, 1)
            );
            assert_eq!((row.sleep_calls_started, row.sleep_calls_completed), (0, 0));
            assert_eq!(row.actual_sleep_wall_ns, None);
            assert_eq!(row.requested_sleep_ns, None);
            assert_eq!(row.span.accepted, Some(true));
        } else {
            assert!(snapshot.is_none());
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn actual_cold_reservation_records_original_refill_sleeps_without_granting_credit() {
    use super::super::public_v3::ServiceMutationCpuDomain;
    let domain = ServiceMutationCpuDomain::cold_remote_history_epoch();
    assert_eq!(domain.observe().unwrap().stored_credit_ns, 0);
    let recorder = NativeAttribution::new(Instant::now());
    let control = Control {
        deadline: Instant::now() + Duration::from_secs(2),
        resource: &|| Ok(()),
    };
    let operation = begin_cpu_observed(&domain, &control, Some(&recorder)).unwrap();
    let row = recorder.snapshot().0.unwrap().cpu_waits[0];
    assert!(row.reserve_attempts > 1);
    assert_eq!(row.reserve_attempts, row.reserve_returns);
    assert_eq!(row.reserve_granted, 1);
    assert_eq!(row.reserve_attempts, row.reserve_budget_refusals + 1);
    assert_eq!(row.sleep_calls_started, row.reserve_budget_refusals);
    assert_eq!(row.sleep_calls_started, row.sleep_calls_completed);
    assert!(row.actual_sleep_wall_ns.unwrap() > 0);
    assert!(row.requested_sleep_ns.unwrap() > 0);
    assert!(
        row.original_deadline_remaining_at_exit_ns.unwrap()
            < row.original_deadline_remaining_at_entry_ns.unwrap()
    );
    assert!(!operation.finish().accounting_unavailable);
    let flow = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(flow.initial_credit_ns, 0);
    assert!(flow.balance_identity_verified);
}

#[cfg(target_os = "linux")]
#[test]
fn original_deadline_and_host_error_still_precede_every_reservation() {
    use super::super::public_v3::ServiceMutationCpuDomain;
    for expired in [true, false] {
        let domain = ServiceMutationCpuDomain::standalone();
        let before = domain.observe_actual_flow().unwrap();
        let recorder = NativeAttribution::new(Instant::now());
        let calls = AtomicUsize::new(0);
        let resource = || {
            calls.fetch_add(1, Ordering::Relaxed);
            Err("PUBLIC_REQUEST_CANCELLED".into())
        };
        let control = Control {
            deadline: Instant::now()
                + if expired {
                    Duration::ZERO
                } else {
                    Duration::from_secs(1)
                },
            resource: &resource,
        };
        let error = begin_cpu_observed(&domain, &control, Some(&recorder))
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            if expired {
                "PUBLIC_REQUEST_DEADLINE"
            } else {
                "PUBLIC_REQUEST_CANCELLED"
            }
        );
        assert_eq!(calls.load(Ordering::Relaxed), usize::from(!expired));
        assert_eq!(domain.observe_actual_flow().unwrap(), before);
        let row = recorder.snapshot().0.unwrap().cpu_waits[0];
        assert_eq!(row.reserve_attempts, 0);
        assert_eq!(row.sleep_calls_started, 0);
        assert_eq!(row.actual_sleep_wall_ns, None);
        assert_eq!(row.span.accepted, Some(false));
        if expired {
            assert_eq!(row.original_deadline_remaining_at_entry_ns, Some(0));
            assert_eq!(row.original_deadline_remaining_at_exit_ns, Some(0));
        }
    }
}

#[test]
fn unfinished_wait_and_capacity_keep_unknown_outcomes_bounded() {
    let recorder = NativeAttribution::new(Instant::now());
    let deadline = Instant::now() + Duration::from_secs(1);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut wait = CpuWaitGuard::new(&recorder, deadline, deadline);
        wait.reserve_started();
        panic!("original reservation did not return");
    }));
    assert!(panicked.is_err());
    let first = recorder.snapshot().0.unwrap().cpu_waits[0];
    assert_eq!((first.reserve_attempts, first.reserve_returns), (1, 0));
    assert!(first.span.unwound && !first.span.completed);
    assert_eq!(first.span.accepted, None);
    for _ in 0..2 {
        CpuWaitGuard::new(&recorder, deadline, deadline).finish(&Ok::<(), crate::Error>(()));
    }
    let (snapshot, failures) = recorder.snapshot();
    assert_eq!(snapshot.unwrap().cpu_waits.len(), MAX_CPU_WAITS);
    assert_eq!(failures, 1);
}

#[test]
fn unknown_clock_and_sleep_totals_are_not_filled_with_zero() {
    let recorder = NativeAttribution::new(Instant::now());
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut wait = CpuWaitGuard::new(&recorder, deadline, deadline);
    wait.span.cpu = None;
    let future = Instant::now() + Duration::from_secs(10);
    wait.sleep_started(Duration::from_millis(1));
    wait.sleep_completed(future); // The exact clock interval is unavailable.
    let start = wait.sleep_started(Duration::ZERO);
    wait.sleep_completed(start);
    wait.finish(&Err::<(), _>("PUBLIC_REQUEST_CANCELLED".into()));
    let row = recorder.snapshot().0.unwrap().cpu_waits[0];
    assert_eq!(row.actual_sleep_wall_ns, None);
    assert_eq!(row.span.thread_cpu_ns, None);
    assert_eq!(row.sleep_calls_completed, 2);
    assert_eq!(row.span.accepted, Some(false));
}
