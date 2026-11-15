use super::legacy_reorg_observation_tests::{fork_pair, lifecycle};
use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

#[derive(Clone, Copy, Debug)]
enum Cut {
    None,
    BeforePublish,
    ExpectedSteps,
    Events,
    Published,
    Unwind,
}
fn run(node: &mut Node, target: Hash, cut: Cut) -> (String, Vec<Hash>, Vec<String>, u64) {
    let sql = Arc::new(Mutex::new(Vec::new()));
    let sql_out = sql.clone();
    let steps = Arc::new(AtomicUsize::new(0));
    let step_trace = steps.clone();
    let events = Arc::new(AtomicBool::new(false));
    let event_trace = events.clone();
    node.db.trace_v2(rusqlite::trace::TraceEventCodes::SQLITE_TRACE_STMT,Some(move |e:rusqlite::trace::TraceEvent<'_>|{if let rusqlite::trace::TraceEvent::Stmt(_,text)=e {
        sql_out.lock().unwrap().push(hash(b"tail-test-sql",&[text.as_bytes()]));
        if text=="SELECT ordinal,kind,block FROM steps ORDER BY ordinal" {step_trace.fetch_add(1,Ordering::SeqCst);}
        if text=="SELECT ordinal,kind,block FROM events WHERE generation=? ORDER BY ordinal" {event_trace.store(true,Ordering::SeqCst);}
    }})).unwrap();
    let mut cuts = Vec::new();
    let mut progress_calls = 0;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node.activate_with_fault_and_progress(
            target,
            Some(&mut |point| {
                cuts.push(point.to_owned());
                if matches!(cut, Cut::Unwind) && point == "before-publish" {
                    panic!("PRIVATE_NATIVE_PANIC");
                }
                if (matches!(cut, Cut::BeforePublish) && point == "before-publish")
                    || (matches!(cut, Cut::Published) && point == "published")
                {
                    return Err(Error::new(crate::ErrorCode::PublicRequestDeadline));
                }
                Ok(())
            }),
            &mut || {
                progress_calls += 1;
                if (matches!(cut, Cut::ExpectedSteps) && steps.load(Ordering::SeqCst) >= 3)
                    || (matches!(cut, Cut::Events) && events.load(Ordering::SeqCst))
                {
                    Err(Error::new(crate::ErrorCode::PublicRequestDeadline))
                } else {
                    Ok(())
                }
            },
            None,
        )
    }));
    node.db
        .trace_v2(
            rusqlite::trace::TraceEventCodes::empty(),
            None::<fn(rusqlite::trace::TraceEvent<'_>)>,
        )
        .unwrap();
    let result = match result {
        Ok(Ok(id)) => format!("ok:{}", hex::encode(id)),
        Ok(Err(e)) => format!("{:?}:{:?}:{}", e.kind(), e.code(), e),
        Err(_) => "unwind".into(),
    };
    let traces = sql.lock().unwrap().clone();
    (result, traces, cuts, progress_calls)
}
#[test]
fn owner_local_tail_switch_preserves_sql_progress_state_errors_and_rollback() {
    for cut in [
        Cut::None,
        Cut::BeforePublish,
        Cut::ExpectedSteps,
        Cut::Events,
        Cut::Published,
        Cut::Unwind,
    ] {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let (mut control, mut observed, target, _) = fork_pair(a.path(), b.path());
        let old = control.read_active().unwrap();
        let clock_before = native_authenticated::legacy_tail_clock_reads();
        assert!(observed.enable_native_legacy_reorg_observation());
        assert!(observed.enable_native_legacy_reorg_observation());
        assert_eq!(
            native_authenticated::legacy_tail_clock_reads(),
            clock_before
        );
        let off = run(&mut control, target, cut);
        assert_eq!(
            native_authenticated::legacy_tail_clock_reads(),
            clock_before,
            "disabled clock read at {cut:?}"
        );
        let on = run(&mut observed, target, cut);
        assert_eq!(off, on, "SQL/progress/result changed at {cut:?}");
        assert!(native_authenticated::legacy_tail_clock_reads() > clock_before);
        assert_eq!(
            control.read_active().unwrap(),
            observed.read_active().unwrap()
        );
        assert_eq!(lifecycle(&control), lifecycle(&observed));
        let events = |n: &Node| {
            n.db.query_row("SELECT count(*) FROM events", [], |r| r.get::<_, u64>(0))
                .unwrap()
        };
        assert_eq!(events(&control), events(&observed));
        let s = observed.native_history_arithmetic_observation();
        let tail = &s["activation_tail"];
        assert_eq!(tail["segments_observed"], 1);
        assert_eq!(tail["observation_failed"], false);
        let expected_phase = match cut {
            Cut::None | Cut::Published => "after_publication",
            Cut::BeforePublish | Cut::Unwind => "before_publication",
            Cut::ExpectedSteps => "expected_steps",
            Cut::Events => "publication_events_check",
        };
        assert_eq!(tail["last_observed_segment"]["last_phase"], expected_phase);
        assert_eq!(
            tail["last_observed_segment"]["completed"],
            matches!(cut, Cut::None)
        );
        assert_eq!(
            tail["last_observed_segment"]["unwound"],
            matches!(cut, Cut::Unwind)
        );
        assert!(!tail.to_string().contains("PUBLIC_REQUEST_DEADLINE"));
        assert!(!tail.to_string().contains("PRIVATE_NATIVE_PANIC"));
        assert!(!tail.to_string().contains(&hex::encode(target)));
        if matches!(cut, Cut::None | Cut::Published) {
            assert_eq!(observed.active().unwrap().0, target);
            assert_eq!(lifecycle(&observed).0, 1);
            assert_eq!(lifecycle(&observed).2, 1);
        } else {
            assert_eq!(observed.read_active().unwrap(), old);
            if !matches!(cut, Cut::Unwind) {
                assert_eq!(lifecycle(&observed).0, 2);
                assert_eq!(lifecycle(&observed).2, 2);
                assert!(off.0.contains("PUBLIC_REQUEST_DEADLINE"));
            }
        }
    }
}
