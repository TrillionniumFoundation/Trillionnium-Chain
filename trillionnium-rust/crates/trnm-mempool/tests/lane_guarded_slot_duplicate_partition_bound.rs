use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn guarded_last_reserved_slot_keeps_fresh_normal_backpressured_while_duplicate_critical_stays_duplicate() {
    let mut gate = LaneAdmissionGate::new(5, 2);

    // Fill dedicated normal capacity, then leave exactly one reserved critical
    // slot free under active critical backlog.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    let guarded = LaneQosSnapshot {
        normal_queued: 3,
        critical_queued: 1,
        total_queued: 4,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(gate.qos_snapshot(), guarded);

    // While the final reserved slot is guarded, fresh normal retries stay
    // backpressured, but the already queued critical id must continue to dedupe
    // across classes instead of degrading to backpressure.
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.admit(10, IngressClass::Critical), AdmitOutcome::Duplicate);
    assert_eq!(gate.qos_snapshot(), guarded);
    assert_eq!(gate.queued_counts(), (3, 1, 4));

    // Fresh critical ingress may still consume the guarded slot, after which the
    // lane becomes fully saturated for both classes.
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

    // Under saturation, the same partition still holds: fresh ids stay
    // backpressured and queued ids stay duplicate.
    assert_eq!(gate.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(gate.admit(11, IngressClass::Normal), AdmitOutcome::Duplicate);
    assert_eq!(gate.admit(11, IngressClass::Critical), AdmitOutcome::Duplicate);
}
