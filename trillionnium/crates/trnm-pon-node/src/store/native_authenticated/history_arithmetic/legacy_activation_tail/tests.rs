use super::*;
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    time::Duration,
};
fn stamp(wall: Option<Instant>, cpu: Option<u64>) -> Stamp {
    Stamp {
        wall,
        cpu,
        thread: thread::current().id(),
    }
}
fn observation(a: Arc<Accounting>, start: Stamp) -> Observation {
    let mut rows = [Row::default(); COUNT];
    rows[0].enter(start.elapsed(start));
    Observation {
        accounting: a,
        origin: start,
        current: Phase::ResumeToLastAttach,
        started: start,
        rows,
        completed: false,
        sealed: false,
    }
}
#[test]
fn disabled_paths_do_not_read_diagnostic_clocks() {
    let h = super::super::HistoryArithmetic::default();
    let before = clock_reads();
    assert!(h.legacy_tail_origin().is_none());
    let mut o = None;
    Observation::advance(&mut o, Phase::FinalState);
    Observation::complete(&mut o);
    assert_eq!(clock_reads(), before);
    assert!(h.legacy_tail.borrow().is_none());
}
#[test]
fn known_boundaries_and_completed_prefix_are_fixed_and_relative() {
    let a = Arc::new(Accounting::default());
    let t = Instant::now();
    let mut o = observation(a.clone(), stamp(Some(t), Some(10)));
    o.advance_at(
        Phase::FinalState,
        stamp(Some(t + Duration::from_nanos(20)), Some(18)),
    );
    o.advance_at(
        Phase::FinalContinuity,
        stamp(Some(t + Duration::from_nanos(50)), Some(30)),
    );
    o.seal(stamp(Some(t + Duration::from_nanos(60)), Some(34)), false);
    let s = a.snapshot();
    let p = &s["last_observed_segment"]["phases"];
    assert_eq!(p.as_array().unwrap().len(), COUNT);
    assert_eq!(p[1]["totals"]["last_entry_elapsed_wall_ns"], 20);
    assert_eq!(p[1]["totals"]["wall_ns"], 30);
    assert_eq!(p[1]["totals"]["completed"], 1);
    assert_eq!(p[2]["totals"]["early_exit"], 1);
    assert!(p[3]["totals"]["wall_ns"].is_null());
    assert_eq!(s["last_observed_segment"]["completed"], false);
}
#[test]
fn missing_reversed_overflow_and_cross_thread_clocks_remain_unknown() {
    let t = Instant::now();
    let start = stamp(Some(t), Some(10));
    assert_eq!(start.elapsed(stamp(None, None)), (None, None));
    assert_eq!(
        stamp(Some(t + Duration::from_nanos(1)), Some(11)).elapsed(start),
        (None, None)
    );
    let other = thread::spawn(|| thread::current().id()).join().unwrap();
    let mut end = stamp(Some(t + Duration::from_nanos(2)), Some(12));
    end.thread = other;
    assert_eq!(start.elapsed(end), (Some(2), None));
    assert!(u64::try_from(Duration::from_secs(u64::MAX).as_nanos()).is_err());
    let mut r = Row::default();
    r.enter((None, None));
    r.close((None, None), true, false);
    r.enter((Some(10), Some(10)));
    r.close((Some(10), Some(10)), true, false);
    assert!(r.wall_ns.is_none() && r.calling_thread_cpu_ns.is_none());
    r.wall_ns = Some(u64::MAX);
    r.calling_thread_cpu_ns = Some(u64::MAX);
    r.close((Some(1), Some(1)), false, false);
    assert!(r.wall_ns.is_none() && r.calling_thread_cpu_ns.is_none());
    r.entered = Some(u64::MAX);
    r.enter((Some(0), Some(0)));
    assert!(r.entered.is_none());
    r.completed = Some(u64::MAX);
    r.samples = Some(u64::MAX);
    r.close((Some(1), Some(1)), true, false);
    assert!(r.completed.is_none() && r.samples.is_none() && r.wall_ns.is_none());
}
#[test]
fn unwinding_retains_prefix_without_error_or_panic_payload() {
    let a = Arc::new(Accounting::default());
    let origin = Origin::new(a.clone());
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut o = Some(origin.begin());
        Observation::advance(&mut o, Phase::FinalState);
        panic!("PRIVATE_PAYLOAD_SENTINEL");
    }));
    assert!(result.is_err());
    let s = a.snapshot();
    assert_eq!(s["segments_unwound"], 1);
    assert_eq!(s["last_observed_segment"]["last_phase"], "final_state");
    assert_eq!(
        s["last_observed_segment"]["phases"][0]["totals"]["completed"],
        1
    );
    assert!(!s.to_string().contains("PRIVATE_PAYLOAD_SENTINEL"));
}
#[test]
fn completion_counts_do_not_reset_and_overflow_is_null() {
    let a = Arc::new(Accounting::default());
    for _ in 0..2 {
        let mut o = Origin::new(a.clone()).begin();
        o.completed = true;
    }
    let s = a.snapshot();
    assert_eq!(s["segments_observed"], 2);
    assert_eq!(s["segments_completed"], 2);
    a.state.lock().unwrap().segments = Some(u64::MAX);
    drop(Origin::new(a.clone()).begin());
    assert!(a.snapshot()["segments_observed"].is_null());
}
#[test]
fn unavailable_accounting_does_not_replace_native_results() {
    let a = Arc::new(Accounting::default());
    let origin = Origin::new(a.clone());
    let held = a.state.lock().unwrap();
    let result: Result<(), &str> = {
        let _o = origin.begin();
        Err("ORIGINAL_ERROR")
    };
    assert_eq!(result, Err("ORIGINAL_ERROR"));
    drop(held);
    let s = a.snapshot();
    assert_eq!(s["observation_failed"], true);
    assert!(s["phases"].is_null());
}
