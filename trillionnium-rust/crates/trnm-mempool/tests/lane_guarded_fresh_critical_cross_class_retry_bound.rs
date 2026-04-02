use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate, LaneQosSnapshot};

#[test]
fn guarded_fresh_critical_cross_class_retry_stays_fresh_and_admits_on_critical_path() {
    let mut g = LaneAdmissionGate::new(4, 2);

    // Fill dedicated normal capacity while leaving one aggregate slot reserved for
    // fresh critical ingress under active critical backlog.
    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);

    let guarded_snapshot = LaneQosSnapshot {
        normal_queued: 2,
        critical_queued: 1,
        total_queued: 3,
        normal_headroom: 0,
        critical_headroom: 1,
        total_headroom: 1,
        fresh_normal_admissible: false,
        fresh_critical_admissible: true,
    };
    assert_eq!(g.qos_snapshot(), guarded_snapshot);

    // A fresh tx first probed through the normal class is reserve-guarded here and
    // must remain fresh rather than being poisoned into duplicate metadata.
    assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Backpressured);
    assert_eq!(g.qos_snapshot(), guarded_snapshot);

    // The same tx id should immediately admit through the critical path because the
    // final reserved slot is genuinely available to fresh critical ingress.
    assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(
        g.qos_snapshot(),
        LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 2,
            total_queued: 4,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        }
    );
}
