use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn borrowed_last_idle_critical_slot_keeps_cross_class_fresh_retry_unpoisoned_until_normal_reopens()
{
    let mut g = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal headroom, then borrow the last idle reserved critical slot.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (2, 1, 3));

    let borrowed_snapshot = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 1,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(g.qos_snapshot(), borrowed_snapshot);

    // A fresh tx blocked on the critical path must stay fresh across opposite-class
    // retries while the borrowed slot remains occupied.
    assert_eq!(
        g.admit(99, IngressClass::Critical),
        AdmitOutcome::Backpressured
    );
    assert_eq!(
        g.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(g.qos_snapshot(), borrowed_snapshot);
    assert_eq!(g.queued_counts(), (2, 1, 3));

    // Once the borrowed occupant drains, the same tx id should still admit as fresh
    // through the normal path instead of being poisoned into Duplicate by the earlier
    // reserve-guarded retries.
    assert_eq!(g.pop_ready(), Some(3));
    let reopened_snapshot = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 0,
        total_queued: 2,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: true,
        fresh_critical_admissible: true,
    };
    assert_eq!(g.qos_snapshot(), reopened_snapshot);

    assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Duplicate);
}
