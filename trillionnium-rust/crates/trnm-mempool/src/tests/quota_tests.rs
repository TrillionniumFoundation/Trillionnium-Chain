use super::*;

#[test]
fn queued_counts_track_spillover_and_drain() {
    let mut g = LaneAdmissionGate::new(4, 1);

    assert_eq!(g.queued_counts(), (0, 0, 0));

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
    // Critical reserve full; tx 51 spills into normal queue.
    assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.queued_counts(), (3, 1, 4));

    assert_eq!(g.pop_ready(), Some(50));
    assert_eq!(g.queued_counts(), (3, 0, 3));

    assert_eq!(g.pop_ready(), Some(1));
    assert_eq!(g.pop_ready(), Some(2));
    assert_eq!(g.pop_ready(), Some(51));
    assert_eq!(g.queued_counts(), (0, 0, 0));
}

#[test]
fn seen_global_len_matches_lane_queues_across_spillover_and_drain() {
    let mut g = LaneAdmissionGate::new(4, 1);

    assert_eq!(g.seen_global.len(), 0);

    assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.seen_global.len(), 1);

    assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
    assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
    // Critical reserve full; tx 51 spills into normal queue.
    assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Accepted);
    assert_eq!(g.seen_global.len(), 4);

    // Backpressured ids must not inflate the queued count invariant.
    assert_eq!(
        g.admit(99, IngressClass::Normal),
        AdmitOutcome::Backpressured
    );
    assert_eq!(g.seen_global.len(), 4);

    let (_, _, total) = g.queued_counts();
    assert_eq!(g.seen_global.len(), total);

    assert_eq!(g.pop_ready(), Some(50));
    assert_eq!(g.pop_ready(), Some(1));
    let (_, _, total_after_drain) = g.queued_counts();
    assert_eq!(g.seen_global.len(), total_after_drain);
}
