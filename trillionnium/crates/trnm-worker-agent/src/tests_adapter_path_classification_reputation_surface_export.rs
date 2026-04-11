use super::*;

#[test]
fn exported_canonical_reputation_surfaces_round_trip_through_all_helper_axes() {
    let surfaces = canonical_reputation_surfaces();
    assert_eq!(surfaces.len(), CANONICAL_REPUTATION_SIGNAL_ORDER.len());

    for (expected_rank, signal) in CANONICAL_REPUTATION_SIGNAL_ORDER.iter().enumerate() {
        let impact = reputation_impact(*signal);
        let surface = surfaces[expected_rank];

        assert_eq!(surface.label, impact.label);
        assert_eq!(surface.delta, impact.delta);
        assert_eq!(surface.tier, impact.tier);
        assert_eq!(surface.weight_bps, reputation_weight_bps(*signal));
        assert_eq!(surface.score_bps, reputation_score_bps(*signal));
        assert_eq!(surface.rank_ordinal, expected_rank as u8);

        assert_eq!(reputation_score_impact(*signal), (surface.label, surface.delta));
        assert_eq!(reputation_signal_from_score_bps(surface.score_bps), Some(*signal));
        assert_eq!(reputation_signal_from_label(surface.label), Some(*signal));
        assert_eq!(reputation_signal_from_delta(surface.delta), Some(*signal));
        assert_eq!(reputation_signal_from_tier(surface.tier), Some(*signal));
        assert_eq!(reputation_signal_from_weight_bps(surface.weight_bps), Some(*signal));
        assert_eq!(reputation_signal_from_rank_ordinal(surface.rank_ordinal), Some(*signal));
        assert_eq!(
            reputation_signal_from_surface(
                surface.label,
                surface.delta,
                surface.tier,
                surface.weight_bps,
                surface.score_bps,
                surface.rank_ordinal,
            ),
            Some(*signal),
            "canonical surface export must remain round-trippable across every score axis"
        );
    }
}

#[test]
fn exported_canonical_reputation_surfaces_fail_closed_on_cross_signal_hybrids() {
    let surfaces = canonical_reputation_surfaces();
    assert!(surfaces.len() >= 2, "expected at least two canonical surfaces");

    let accepted = surfaces[0];
    let retryable = surfaces[1];

    assert_eq!(
        reputation_signal_from_surface(
            accepted.label,
            accepted.delta,
            accepted.tier,
            retryable.weight_bps,
            accepted.score_bps,
            accepted.rank_ordinal,
        ),
        None,
        "surface lookup must reject cross-signal weight hybrids"
    );
    assert_eq!(
        reputation_signal_from_surface(
            accepted.label,
            accepted.delta,
            retryable.tier,
            accepted.weight_bps,
            accepted.score_bps,
            accepted.rank_ordinal,
        ),
        None,
        "surface lookup must reject cross-signal tier hybrids"
    );
    assert_eq!(
        reputation_signal_from_surface(
            accepted.label,
            retryable.delta,
            accepted.tier,
            accepted.weight_bps,
            accepted.score_bps,
            accepted.rank_ordinal,
        ),
        None,
        "surface lookup must reject cross-signal delta hybrids"
    );
    assert_eq!(
        reputation_signal_from_surface(
            accepted.label,
            accepted.delta,
            accepted.tier,
            accepted.weight_bps,
            retryable.score_bps,
            accepted.rank_ordinal,
        ),
        None,
        "surface lookup must reject cross-signal normalized score hybrids"
    );
    assert_eq!(
        reputation_signal_from_surface(
            accepted.label,
            accepted.delta,
            accepted.tier,
            accepted.weight_bps,
            accepted.score_bps,
            retryable.rank_ordinal,
        ),
        None,
        "surface lookup must reject cross-signal rank hybrids"
    );
}

#[test]
fn exported_canonical_reputation_surfaces_keep_unique_score_bps_per_signal() {
    let surfaces = canonical_reputation_surfaces();

    for (idx, surface) in surfaces.iter().enumerate() {
        assert_eq!(
            reputation_signal_from_score_bps(surface.score_bps),
            Some(CANONICAL_REPUTATION_SIGNAL_ORDER[idx]),
            "score_bps must round-trip to exactly one canonical signal"
        );

        for other in surfaces.iter().skip(idx + 1) {
            assert_ne!(
                surface.score_bps, other.score_bps,
                "each canonical surface must keep a unique normalized score"
            );
        }
    }
}

#[test]
fn exported_canonical_reputation_surfaces_keep_strictly_descending_score_bps() {
    let surfaces = canonical_reputation_surfaces();

    for window in surfaces.windows(2) {
        let current = window[0];
        let next = window[1];
        assert!(
            current.score_bps > next.score_bps,
            "normalized score surface must remain strictly descending across canonical rank order"
        );
    }
}
