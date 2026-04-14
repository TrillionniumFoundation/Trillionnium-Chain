use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn borrowed_last_idle_critical_slot_keeps_qos_snapshot_flat_across_retry_and_duplicate_noise() {
    let mut gate = LaneAdmissionGate::new(3, 1);

    // Fill dedicated normal capacity, then borrow the final idle reserved slot.
    assert_eq!(gate.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(gate.queued_counts(), (2, 1, 3));

    let borrowed_full = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 1,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 0,
        total_headroom: 0,
        fresh_normal_admissible: false,
        fresh_critical_admissible: false,
    };
    assert_eq!(gate.qos_snapshot(), borrowed_full);

    // While the borrowed occupant still owns the last reserved slot, fresh
    // critical retries must stay backpressured and duplicate probes for the
    // borrowed id must stay duplicate, without perturbing the public snapshot.
    for _ in 0..3 {
        assert_eq!(
            gate.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            gate.admit(3, IngressClass::Critical),
            AdmitOutcome::Duplicate
        );
        assert_eq!(gate.admit(3, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(gate.queued_counts(), (2, 1, 3));
        assert_eq!(gate.qos_snapshot(), borrowed_full);
    }

    // Once the borrowed occupant drains and the critical lane becomes idle, the
    // final reserved slot should immediately reopen for both fresh classes.
    assert_eq!(gate.pop_ready(), Some(3));
    assert_eq!(gate.queued_counts(), (2, 0, 2));
    assert_eq!(
        gate.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 0,
            total_queued: 2,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        }
    );
}
