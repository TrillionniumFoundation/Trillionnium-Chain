use super::*;

#[test]
fn full_drain_resets_fairness_streak_so_next_critical_is_not_delayed() {
    let mut gate = LaneAdmissionGate::new(6, 2);

    // Warm a non-zero critical streak with active critical dequeues.
    assert_eq!(
        gate.admit(100, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(
        gate.admit(101, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(100));

    // Drain fully so the scheduler should reset warm fairness state.
    assert_eq!(gate.pop_ready(), Some(101));
    assert_eq!(gate.pop_ready(), None);

    // After idle reset, a fresh critical item should be served immediately.
    assert_eq!(
        gate.admit(200, IngressClass::Critical),
        AdmitOutcome::Accepted
    );
    assert_eq!(gate.pop_ready(), Some(200));
}
