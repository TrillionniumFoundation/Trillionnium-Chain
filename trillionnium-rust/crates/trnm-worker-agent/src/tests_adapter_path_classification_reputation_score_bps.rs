use super::*;

#[test]
fn reputation_score_bps_normalizes_canonical_deltas_into_signed_basis_points() {
    assert_eq!(reputation_score_bps(ReputationSignal::Accepted), 10_000);
    assert_eq!(
        reputation_score_bps(ReputationSignal::AdapterRetryExhausted),
        -3_333
    );
    assert_eq!(reputation_score_bps(ReputationSignal::VerifierRejected), -6_666);
    assert_eq!(
        reputation_score_bps(ReputationSignal::AdapterNonRetriable),
        -10_000
    );
}

#[test]
fn reputation_score_bps_round_trips_back_to_canonical_signal_and_impact() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let score_bps = reputation_score_bps(signal);
        let impact = reputation_impact(signal);
        assert_eq!(reputation_signal_from_score_bps(score_bps), Some(signal));
        assert_eq!(reputation_impact_from_score_bps(score_bps), Some(impact));
    }
}

#[test]
fn reputation_score_bps_lookup_fails_closed_on_non_canonical_values() {
    assert_eq!(reputation_signal_from_score_bps(0), None);
    assert_eq!(reputation_signal_from_score_bps(9_999), None);
    assert_eq!(reputation_signal_from_score_bps(-3_334), None);
    assert_eq!(reputation_impact_from_score_bps(-6_667), None);
}

#[test]
fn reputation_score_bps_stays_strictly_descending_across_canonical_order() {
    let mut previous: Option<i32> = None;
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let score_bps = reputation_score_bps(signal);
        if let Some(prev) = previous {
            assert!(
                prev > score_bps,
                "normalized score bps must remain strictly descending across canonical order"
            );
        }
        previous = Some(score_bps);
    }
}

#[test]
fn reputation_gap_bps_from_best_exposes_deterministic_distance_from_accepted() {
    assert_eq!(reputation_gap_bps_from_best(ReputationSignal::Accepted), 0);
    assert_eq!(
        reputation_gap_bps_from_best(ReputationSignal::AdapterRetryExhausted),
        13_333
    );
    assert_eq!(
        reputation_gap_bps_from_best(ReputationSignal::VerifierRejected),
        16_666
    );
    assert_eq!(
        reputation_gap_bps_from_best(ReputationSignal::AdapterNonRetriable),
        20_000
    );
}

#[test]
fn reputation_gap_bps_from_best_stays_strictly_increasing_across_canonical_order() {
    let mut previous: Option<i32> = None;
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let gap_bps = reputation_gap_bps_from_best(signal);
        if let Some(prev) = previous {
            assert!(
                prev < gap_bps,
                "gap from best must remain strictly increasing across canonical order"
            );
        }
        previous = Some(gap_bps);
    }
}
