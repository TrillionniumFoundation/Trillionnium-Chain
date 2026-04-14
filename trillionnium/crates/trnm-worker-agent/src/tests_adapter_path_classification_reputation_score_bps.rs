use super::*;

#[test]
fn reputation_score_bps_normalizes_canonical_deltas_into_signed_basis_points() {
    assert_eq!(reputation_score_bps(ReputationSignal::Accepted), 10_000);
    assert_eq!(
        reputation_score_bps(ReputationSignal::AdapterRetryExhausted),
        -3_333
    );
    assert_eq!(
        reputation_score_bps(ReputationSignal::VerifierRejected),
        -6_666
    );
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

#[test]
fn reputation_gap_bps_from_best_round_trips_back_to_canonical_signal_and_impact() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let gap_bps = reputation_gap_bps_from_best(signal);
        let impact = reputation_impact(signal);
        assert_eq!(
            reputation_signal_from_gap_bps_from_best(gap_bps),
            Some(signal)
        );
        assert_eq!(
            reputation_impact_from_gap_bps_from_best(gap_bps),
            Some(impact)
        );
    }
}

#[test]
fn reputation_gap_bps_from_best_lookup_fails_closed_on_non_canonical_values() {
    assert_eq!(reputation_signal_from_gap_bps_from_best(-1), None);
    assert_eq!(reputation_signal_from_gap_bps_from_best(1), None);
    assert_eq!(reputation_signal_from_gap_bps_from_best(13_334), None);
    assert_eq!(reputation_impact_from_gap_bps_from_best(19_999), None);
}

#[test]
fn reputation_gap_bps_from_worst_exposes_deterministic_distance_from_lowest_surface() {
    assert_eq!(
        reputation_gap_bps_from_worst(ReputationSignal::Accepted),
        20_000
    );
    assert_eq!(
        reputation_gap_bps_from_worst(ReputationSignal::AdapterRetryExhausted),
        6_667
    );
    assert_eq!(
        reputation_gap_bps_from_worst(ReputationSignal::VerifierRejected),
        3_334
    );
    assert_eq!(
        reputation_gap_bps_from_worst(ReputationSignal::AdapterNonRetriable),
        0
    );
}

#[test]
fn reputation_gap_bps_from_worst_round_trips_back_to_canonical_signal_and_impact() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let gap_bps = reputation_gap_bps_from_worst(signal);
        let impact = reputation_impact(signal);
        assert_eq!(
            reputation_signal_from_gap_bps_from_worst(gap_bps),
            Some(signal)
        );
        assert_eq!(
            reputation_impact_from_gap_bps_from_worst(gap_bps),
            Some(impact)
        );
    }
}

#[test]
fn reputation_gap_bps_from_worst_lookup_fails_closed_on_non_canonical_values() {
    assert_eq!(reputation_signal_from_gap_bps_from_worst(-1), None);
    assert_eq!(reputation_signal_from_gap_bps_from_worst(1), None);
    assert_eq!(reputation_signal_from_gap_bps_from_worst(6_666), None);
    assert_eq!(reputation_impact_from_gap_bps_from_worst(19_999), None);
}

#[test]
fn reputation_gap_pair_round_trips_back_to_canonical_signal_and_impact() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let gap_bps_from_best = reputation_gap_bps_from_best(signal);
        let gap_bps_from_worst = reputation_gap_bps_from_worst(signal);
        let impact = reputation_impact(signal);

        assert_eq!(
            reputation_signal_from_gap_pair(gap_bps_from_best, gap_bps_from_worst),
            Some(signal)
        );
        assert_eq!(
            reputation_impact_from_gap_pair(gap_bps_from_best, gap_bps_from_worst),
            Some(impact)
        );
    }
}

#[test]
fn reputation_gap_pair_lookup_fails_closed_on_cross_signal_hybrids() {
    let accepted = ReputationSignal::Accepted;
    let verifier_rejected = ReputationSignal::VerifierRejected;

    assert_eq!(
        reputation_signal_from_gap_pair(
            reputation_gap_bps_from_best(accepted),
            reputation_gap_bps_from_worst(verifier_rejected)
        ),
        None
    );
    assert_eq!(
        reputation_impact_from_gap_pair(
            reputation_gap_bps_from_best(verifier_rejected),
            reputation_gap_bps_from_worst(accepted)
        ),
        None
    );
}

#[test]
fn reputation_rank_gap_and_score_axes_stay_in_lockstep() {
    let accepted_score_bps = reputation_score_bps(ReputationSignal::Accepted);
    let worst_score_bps = reputation_score_bps(ReputationSignal::AdapterNonRetriable);

    for (expected_rank, signal) in CANONICAL_REPUTATION_SIGNAL_ORDER.iter().enumerate() {
        let score_bps = reputation_score_bps(*signal);
        let gap_bps = reputation_gap_bps_from_best(*signal);
        let gap_from_worst_bps = reputation_gap_bps_from_worst(*signal);
        let rank_ordinal = reputation_rank_ordinal(*signal);
        let impact = reputation_impact(*signal);

        assert_eq!(rank_ordinal, expected_rank as u8);
        assert_eq!(
            reputation_signal_from_rank_ordinal(rank_ordinal),
            Some(*signal)
        );
        assert_eq!(
            reputation_impact_from_rank_ordinal(rank_ordinal),
            Some(impact)
        );
        assert_eq!(score_bps + gap_bps, accepted_score_bps);
        assert_eq!(score_bps - gap_from_worst_bps, worst_score_bps);
        assert_eq!(
            gap_bps + gap_from_worst_bps,
            accepted_score_bps - worst_score_bps
        );

        if expected_rank > 0 {
            let prev = CANONICAL_REPUTATION_SIGNAL_ORDER[expected_rank - 1];
            assert!(
                reputation_gap_bps_from_best(prev) < gap_bps,
                "higher rank ordinals must always sit farther from the accepted baseline"
            );
            assert!(
                reputation_gap_bps_from_worst(prev) > gap_from_worst_bps,
                "higher rank ordinals must always sit closer to the worst surface"
            );
            assert!(
                reputation_score_bps(prev) > score_bps,
                "higher rank ordinals must always keep a strictly worse normalized score"
            );
        }
    }
}

#[test]
fn reputation_numeric_surface_exports_stay_one_to_one_per_signal() {
    for (idx, signal) in CANONICAL_REPUTATION_SIGNAL_ORDER.iter().enumerate() {
        let score_bps = reputation_score_bps(*signal);
        let gap_bps_from_best = reputation_gap_bps_from_best(*signal);
        let gap_bps_from_worst = reputation_gap_bps_from_worst(*signal);
        let rank_ordinal = reputation_rank_ordinal(*signal);

        assert_eq!(reputation_signal_from_score_bps(score_bps), Some(*signal));
        assert_eq!(
            reputation_signal_from_gap_bps_from_best(gap_bps_from_best),
            Some(*signal)
        );
        assert_eq!(
            reputation_signal_from_gap_bps_from_worst(gap_bps_from_worst),
            Some(*signal)
        );
        assert_eq!(
            reputation_signal_from_gap_pair(gap_bps_from_best, gap_bps_from_worst),
            Some(*signal)
        );
        assert_eq!(
            reputation_signal_from_rank_ordinal(rank_ordinal),
            Some(*signal)
        );

        for other in CANONICAL_REPUTATION_SIGNAL_ORDER.iter().skip(idx + 1) {
            assert_ne!(score_bps, reputation_score_bps(*other));
            assert_ne!(gap_bps_from_best, reputation_gap_bps_from_best(*other));
            assert_ne!(gap_bps_from_worst, reputation_gap_bps_from_worst(*other));
            assert_ne!(rank_ordinal, reputation_rank_ordinal(*other));
            assert_ne!(
                (gap_bps_from_best, gap_bps_from_worst),
                (
                    reputation_gap_bps_from_best(*other),
                    reputation_gap_bps_from_worst(*other)
                )
            );
        }
    }
}
