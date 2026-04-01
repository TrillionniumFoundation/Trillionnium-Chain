use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn guarded_fresh_normal_reopens_as_fresh_after_final_critical_drain() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Exhaust dedicated normal capacity and leave exactly one aggregate slot
    // guarded for critical ingress while critical backlog is active.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 1, 4));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 3,
            critical_queued: 1,
            total_queued: 4,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        }
    );

    // A fresh normal id remains backpressured under the guarded final reserved slot,
    // but it must stay fresh rather than being poisoned into duplicate metadata.
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // A second critical tx may still claim the final guarded slot.
    assert_eq!(gate.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 2, 5));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 3,
            critical_queued: 2,
            total_queued: 5,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );

    // Draining only one critical item keeps active critical backlog, so the same
    // normal id must remain fresh-but-guarded instead of becoming duplicate.
    assert_eq!(gate.pop_ready(), Some(10));
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.queued_counts(), (3, 1, 4));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 3,
            critical_queued: 1,
            total_queued: 4,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        }
    );

    // Once critical backlog fully clears, the previously guarded id must admit as
    // fresh and immediately become globally duplicate across classes.
    assert_eq!(gate.pop_ready(), Some(11));
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(99, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.queued_counts(), (3, 1, 4));
}
