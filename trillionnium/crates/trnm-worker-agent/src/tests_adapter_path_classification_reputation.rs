use super::*;
#[test]
fn reputation_delta_maps_market_penalty_and_reward_signals() {
    assert_eq!(reputation_delta(ReputationSignal::Accepted), 3);
    assert_eq!(reputation_delta(ReputationSignal::VerifierRejected), -2);
    assert_eq!(
        reputation_delta(ReputationSignal::AdapterRetryExhausted),
        -1
    );
    assert_eq!(reputation_delta(ReputationSignal::AdapterNonRetriable), -3);
}

#[test]
fn reputation_impact_exposes_stable_labels_deltas_and_tiers() {
    assert_eq!(
        reputation_impact(ReputationSignal::Accepted),
        ReputationImpact {
            label: "accepted",
            delta: 3,
            tier: 3,
        }
    );
    assert_eq!(
        reputation_impact(ReputationSignal::AdapterRetryExhausted),
        ReputationImpact {
            label: "adapter_retry_exhausted",
            delta: -1,
            tier: 2,
        }
    );
    assert_eq!(
        reputation_impact(ReputationSignal::VerifierRejected),
        ReputationImpact {
            label: "verifier_rejected",
            delta: -2,
            tier: 1,
        }
    );
    assert_eq!(
        reputation_impact(ReputationSignal::AdapterNonRetriable),
        ReputationImpact {
            label: "adapter_non_retriable",
            delta: -3,
            tier: 0,
        }
    );
}

#[test]
fn reputation_tiers_match_score_ordering() {
    assert!(reputation_tier(ReputationSignal::Accepted) > reputation_tier(ReputationSignal::AdapterRetryExhausted));
    assert!(reputation_tier(ReputationSignal::AdapterRetryExhausted) > reputation_tier(ReputationSignal::VerifierRejected));
    assert!(reputation_tier(ReputationSignal::VerifierRejected) > reputation_tier(ReputationSignal::AdapterNonRetriable));
}

#[test]
fn reputation_weight_bps_exposes_dense_deterministic_rank_surface() {
    assert_eq!(reputation_weight_bps(ReputationSignal::Accepted), 10_000);
    assert_eq!(reputation_weight_bps(ReputationSignal::AdapterRetryExhausted), 6_666);
    assert_eq!(reputation_weight_bps(ReputationSignal::VerifierRejected), 3_333);
    assert_eq!(reputation_weight_bps(ReputationSignal::AdapterNonRetriable), 0);
}

#[test]
fn reputation_surface_exposes_label_delta_tier_and_weight_via_single_mapping_path() {
    assert_eq!(
        reputation_surface(ReputationSignal::Accepted),
        ReputationSurface {
            label: "accepted",
            delta: 3,
            tier: 3,
            weight_bps: 10_000,
            score_bps: 10_000,
            rank_ordinal: 0,
        }
    );
    assert_eq!(
        reputation_surface(ReputationSignal::AdapterRetryExhausted),
        ReputationSurface {
            label: "adapter_retry_exhausted",
            delta: -1,
            tier: 2,
            weight_bps: 6_666,
            score_bps: -3_333,
            rank_ordinal: 1,
        }
    );
    assert_eq!(
        reputation_surface(ReputationSignal::VerifierRejected),
        ReputationSurface {
            label: "verifier_rejected",
            delta: -2,
            tier: 1,
            weight_bps: 3_333,
            score_bps: -6_666,
            rank_ordinal: 2,
        }
    );
    assert_eq!(
        reputation_surface(ReputationSignal::AdapterNonRetriable),
        ReputationSurface {
            label: "adapter_non_retriable",
            delta: -3,
            tier: 0,
            weight_bps: 0,
            score_bps: -10_000,
            rank_ordinal: 3,
        }
    );
}

#[test]
fn reputation_score_impact_exposes_stable_labels_and_deltas() {
    assert_eq!(
        reputation_score_impact(ReputationSignal::Accepted),
        ("accepted", 3)
    );
    assert_eq!(
        reputation_score_impact(ReputationSignal::VerifierRejected),
        ("verifier_rejected", -2)
    );
    assert_eq!(
        reputation_score_impact(ReputationSignal::AdapterRetryExhausted),
        ("adapter_retry_exhausted", -1)
    );
    assert_eq!(
        reputation_score_impact(ReputationSignal::AdapterNonRetriable),
        ("adapter_non_retriable", -3)
    );
}

#[test]
fn verifier_rejection_penalty_sits_between_retryable_and_non_retriable_adapter_failures() {
    let verifier_penalty = reputation_delta(ReputationSignal::VerifierRejected);
    let retryable_penalty = reputation_delta(ReputationSignal::AdapterRetryExhausted);
    let non_retriable_penalty = reputation_delta(ReputationSignal::AdapterNonRetriable);

    assert!(
        verifier_penalty < retryable_penalty,
        "verifier rejection should be stricter than transient adapter exhaustion"
    );
    assert!(
        verifier_penalty > non_retriable_penalty,
        "verifier rejection should remain less severe than deterministic adapter failures"
    );
}

#[test]
fn market_verification_reputation_tiers_remain_strictly_ordered() {
    let accepted = reputation_delta(ReputationSignal::Accepted);
    let retryable = reputation_delta(ReputationSignal::AdapterRetryExhausted);
    let verifier_rejected = reputation_delta(ReputationSignal::VerifierRejected);
    let non_retriable = reputation_delta(ReputationSignal::AdapterNonRetriable);

    assert!(accepted > 0, "accepted work must remain net-positive");
    assert!(retryable < 0, "retry exhaustion must remain a penalty");
    assert!(
        accepted > retryable && retryable > verifier_rejected && verifier_rejected > non_retriable,
        "expected strict tiering: accepted > retryable > verifier_rejected > non_retriable"
    );
}

#[test]
fn adapter_error_signal_maps_retryability_to_penalty_tier() {
    assert_eq!(
        adapter_error_signal(AdapterErrorKind::Retriable),
        ReputationSignal::AdapterRetryExhausted
    );
    assert_eq!(
        adapter_error_signal(AdapterErrorKind::NonRetriable),
        ReputationSignal::AdapterNonRetriable
    );
}

#[test]
fn reputation_score_impact_remains_one_to_one_across_signals() {
    let impacts = [
        reputation_score_impact(ReputationSignal::Accepted),
        reputation_score_impact(ReputationSignal::VerifierRejected),
        reputation_score_impact(ReputationSignal::AdapterRetryExhausted),
        reputation_score_impact(ReputationSignal::AdapterNonRetriable),
    ];

    for (idx, impact) in impacts.iter().enumerate() {
        assert!(
            impacts.iter().skip(idx + 1).all(|other| other != impact),
            "each reputation signal must keep a unique label+delta impact"
        );
    }
}

#[test]
fn reputation_tier_delta_and_label_ordering_stay_monotonic() {
    let mut previous: Option<ReputationImpact> = None;
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let impact = reputation_impact(signal);
        assert_eq!(
            reputation_score_impact(signal),
            (impact.label, impact.delta),
            "score-impact tuple must stay derived from the canonical impact mapping"
        );
        assert_eq!(
            reputation_tier(signal),
            impact.tier,
            "tier helper must stay derived from the canonical impact mapping"
        );

        if let Some(prev) = previous {
            assert!(
                prev.tier > impact.tier,
                "reputation tiers must remain strictly descending along the canonical ordering"
            );
            assert!(
                prev.delta > impact.delta,
                "reputation deltas must remain strictly descending along the canonical ordering"
            );
        }

        previous = Some(impact);
    }
}

#[test]
fn canonical_reputation_signal_order_matches_descending_tier_and_delta() {
    let canonical = CANONICAL_REPUTATION_SIGNAL_ORDER;
    assert_eq!(canonical.len(), 4);

    let mut previous: Option<ReputationImpact> = None;
    for signal in canonical {
        let impact = reputation_impact(signal);
        if let Some(prev) = previous {
            assert!(
                prev.tier > impact.tier,
                "canonical signal order must remain strictly descending by tier"
            );
            assert!(
                prev.delta > impact.delta,
                "canonical signal order must remain strictly descending by delta"
            );
        }
        previous = Some(impact);
    }
}

#[test]
fn canonical_reputation_impact_table_matches_signal_order_and_mapping_helpers() {
    assert_eq!(
        CANONICAL_REPUTATION_IMPACTS.len(),
        CANONICAL_REPUTATION_SIGNAL_ORDER.len(),
        "canonical impact table must stay in lockstep with the signal ordering"
    );

    for ((signal, impact), ordered_signal) in CANONICAL_REPUTATION_IMPACTS
        .iter()
        .zip(CANONICAL_REPUTATION_SIGNAL_ORDER.iter())
    {
        assert_eq!(signal, ordered_signal);
        assert_eq!(reputation_impact(*signal), *impact);
        assert_eq!(reputation_score_impact(*signal), (impact.label, impact.delta));
        assert_eq!(reputation_tier(*signal), impact.tier);
        assert_eq!(reputation_signal_from_delta(impact.delta), Some(*signal));
        assert_eq!(reputation_impact_from_delta(impact.delta), Some(*impact));
    }
}

#[test]
fn canonical_reputation_table_keeps_dense_tiers_and_unit_penalty_steps() {
    for (idx, (_, impact)) in CANONICAL_REPUTATION_IMPACTS.iter().enumerate() {
        let expected_tier = (CANONICAL_REPUTATION_IMPACTS.len() - 1 - idx) as u8;
        assert_eq!(
            impact.tier, expected_tier,
            "canonical tiers must remain dense and gap-free for deterministic ranking"
        );

        if idx > 0 {
            let previous = CANONICAL_REPUTATION_IMPACTS[idx - 1].1;
            assert!(
                previous.delta > impact.delta,
                "adjacent canonical impacts must remain strictly descending"
            );
            if idx > 1 {
                assert_eq!(
                    previous.delta - impact.delta,
                    1,
                    "penalty-side canonical impacts must remain spaced by exactly one score point"
                );
            }
            assert_eq!(
                previous.tier - impact.tier,
                1,
                "adjacent canonical tiers must remain spaced by exactly one tier"
            );
        }
    }
}

#[test]
fn canonical_reputation_weight_bps_descends_monotonically_with_tiers() {
    let mut previous: Option<u16> = None;
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let weight_bps = reputation_weight_bps(signal);
        if let Some(prev) = previous {
            assert!(
                prev > weight_bps,
                "canonical weight surface must remain strictly descending for deterministic ranking"
            );
        }
        previous = Some(weight_bps);
    }
}

#[test]
fn reputation_rank_ordinal_matches_canonical_signal_order() {
    for (expected_rank, signal) in CANONICAL_REPUTATION_SIGNAL_ORDER.iter().enumerate() {
        assert_eq!(reputation_rank_ordinal(*signal), expected_rank as u8);
        assert_eq!(
            reputation_signal_from_rank_ordinal(expected_rank as u8),
            Some(*signal)
        );
        assert_eq!(
            reputation_impact_from_rank_ordinal(expected_rank as u8),
            Some(reputation_impact(*signal))
        );
    }

    assert_eq!(
        reputation_signal_from_rank_ordinal(CANONICAL_REPUTATION_SIGNAL_ORDER.len() as u8),
        None,
        "rank lookup must fail closed past the canonical table"
    );
    assert_eq!(
        reputation_impact_from_rank_ordinal(CANONICAL_REPUTATION_SIGNAL_ORDER.len() as u8),
        None,
        "impact lookup must fail closed past the canonical table"
    );
}

#[test]
fn reputation_weight_bps_round_trips_back_to_canonical_signal_and_impact() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let weight_bps = reputation_weight_bps(signal);
        let impact = reputation_impact(signal);
        assert_eq!(reputation_signal_from_weight_bps(weight_bps), Some(signal));
        assert_eq!(reputation_impact_from_weight_bps(weight_bps), Some(impact));
    }

    assert_eq!(reputation_signal_from_weight_bps(9_999), None);
    assert_eq!(reputation_impact_from_weight_bps(9_999), None);
}

#[test]
fn reputation_delta_round_trips_back_to_canonical_signal_and_impact() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let impact = reputation_impact(signal);
        assert_eq!(reputation_signal_from_delta(impact.delta), Some(signal));
        assert_eq!(reputation_impact_from_delta(impact.delta), Some(impact));
    }

    assert_eq!(reputation_signal_from_delta(0), None);
    assert_eq!(reputation_impact_from_delta(0), None);
}

#[test]
fn reputation_tier_round_trips_back_to_canonical_signal_and_impact() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let impact = reputation_impact(signal);
        assert_eq!(reputation_signal_from_tier(impact.tier), Some(signal));
        assert_eq!(reputation_impact_from_tier(impact.tier), Some(impact));
    }

    assert_eq!(reputation_signal_from_tier(u8::MAX), None);
    assert_eq!(reputation_impact_from_tier(u8::MAX), None);
}

#[test]
fn reputation_label_round_trips_back_to_canonical_signal_and_impact() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let impact = reputation_impact(signal);
        assert_eq!(reputation_signal_from_label(impact.label), Some(signal));
        assert_eq!(reputation_impact_from_label(impact.label), Some(impact));
    }

    assert_eq!(reputation_signal_from_label("unknown"), None);
    assert_eq!(reputation_impact_from_label("unknown"), None);
}

#[test]
fn reputation_label_lookup_accepts_benign_formatting_variants() {
    assert_eq!(
        reputation_signal_from_label(" Accepted "),
        Some(ReputationSignal::Accepted)
    );
    assert_eq!(
        reputation_signal_from_label("adapter retry exhausted"),
        Some(ReputationSignal::AdapterRetryExhausted)
    );
    assert_eq!(
        reputation_signal_from_label("VERIFIER-REJECTED"),
        Some(ReputationSignal::VerifierRejected)
    );
    assert_eq!(
        reputation_impact_from_label("adapter non retriable"),
        Some(reputation_impact(ReputationSignal::AdapterNonRetriable))
    );
    assert_eq!(reputation_signal_from_label("   \n\t  "), None);
}

#[test]
fn reputation_score_impact_pair_round_trips_fail_closed_on_hybrid_tuples() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let impact = reputation_impact(signal);
        assert_eq!(
            reputation_signal_from_score_impact(impact.label, impact.delta),
            Some(signal)
        );
        assert_eq!(
            reputation_impact_from_score_impact(impact.label, impact.delta),
            Some(impact)
        );
    }

    assert_eq!(
        reputation_signal_from_score_impact("accepted", -1),
        None,
        "mixed label+delta tuples must fail closed"
    );
    assert_eq!(
        reputation_impact_from_score_impact("verifier_rejected", 3),
        None,
        "score-impact lookup must reject cross-signal hybrids"
    );
}

#[test]
fn canonical_reputation_table_keeps_label_delta_and_tier_lookups_one_to_one() {
    for (idx, (signal, impact)) in CANONICAL_REPUTATION_IMPACTS.iter().enumerate() {
        assert_eq!(reputation_signal_from_label(impact.label), Some(*signal));
        assert_eq!(reputation_signal_from_delta(impact.delta), Some(*signal));
        assert_eq!(reputation_signal_from_tier(impact.tier), Some(*signal));

        for (other_signal, other_impact) in CANONICAL_REPUTATION_IMPACTS.iter().skip(idx + 1) {
            assert_ne!(impact.label, other_impact.label);
            assert_ne!(impact.delta, other_impact.delta);
            assert_ne!(impact.tier, other_impact.tier);
            assert_ne!(signal, other_signal);
        }
    }
}

#[test]
fn reputation_surface_round_trips_back_to_canonical_signal_and_impact() {
    for signal in CANONICAL_REPUTATION_SIGNAL_ORDER {
        let surface = reputation_surface(signal);
        let impact = reputation_impact(signal);
        assert_eq!(
            reputation_signal_from_surface(
                surface.label,
                surface.delta,
                surface.tier,
                surface.weight_bps,
                surface.score_bps,
                surface.rank_ordinal,
            ),
            Some(signal)
        );
        assert_eq!(
            reputation_impact_from_surface(
                surface.label,
                surface.delta,
                surface.tier,
                surface.weight_bps,
                surface.score_bps,
                surface.rank_ordinal,
            ),
            Some(impact)
        );
    }

    assert_eq!(
        reputation_signal_from_surface("accepted", 3, 3, 9_999, 10_000, 0),
        None,
        "surface lookup must reject weight drift"
    );
    assert_eq!(
        reputation_signal_from_surface("accepted", 3, 2, 10_000, 10_000, 0),
        None,
        "surface lookup must reject tier drift"
    );
    assert_eq!(
        reputation_signal_from_surface("accepted", 3, 3, 10_000, 9_999, 0),
        None,
        "surface lookup must reject score drift"
    );
    assert_eq!(
        reputation_signal_from_surface("accepted", 3, 3, 10_000, 10_000, 1),
        None,
        "surface lookup must reject rank drift"
    );
    assert_eq!(
        reputation_impact_from_surface("verifier_rejected", -2, 1, 10_000, -6_666, 2),
        None,
        "surface lookup must fail closed on cross-signal weight hybrids"
    );
}

#[test]
fn canonical_reputation_surfaces_export_single_deterministic_table() {
    let surfaces = canonical_reputation_surfaces();
    assert_eq!(surfaces.len(), CANONICAL_REPUTATION_SIGNAL_ORDER.len());

    for ((signal, impact), surface) in CANONICAL_REPUTATION_IMPACTS.iter().zip(surfaces.iter()) {
        assert_eq!(surface.label, impact.label);
        assert_eq!(surface.delta, impact.delta);
        assert_eq!(surface.tier, impact.tier);
        assert_eq!(surface.weight_bps, reputation_weight_bps(*signal));
        assert_eq!(surface.rank_ordinal, reputation_rank_ordinal(*signal));
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
            "canonical surface export must stay aligned with reverse lookup helpers"
        );
    }
}

#[test]
fn apply_reputation_signal_updates_record_via_single_mapping_path() {
    let mut rec = MessageIngressRecord {
        request_id: "req-reputation-apply".to_string(),
        task_id: 1500,
        channel: "telegram".to_string(),
        user_id: "u1".to_string(),
        session_id: "s1".to_string(),
        text: "hello".to_string(),
        idempotency_key: "ik-reputation-apply".to_string(),
        status: RequestStatus::Assigned.as_str().to_string(),
        created_at_unix_ms: 1,
        assigned_worker: Some("worker-1".to_string()),
        assigned_at_unix_ms: Some(2),
        model_output: None,
        provider_request_id: None,
        provenance_schema_version: None,
        llm_provenance: None,
        result_hash: None,
        verifier_status: None,
        resolution_code: None,
        commit_tx_hash: None,
        reveal_tx_hash: None,
        adapter_error: None,
        reputation_delta: None,
    };

    let impact = apply_reputation_signal(&mut rec, ReputationSignal::VerifierRejected);
    assert_eq!(impact.label, "verifier_rejected");
    assert_eq!(impact.delta, -2);
    assert_eq!(impact.tier, 1);
    assert_eq!(impact.weight_bps, 3_333);
    assert_eq!(impact.score_bps, -6_666);
    assert_eq!(impact.rank_ordinal, 2);
    assert_eq!(rec.reputation_delta, Some(-2));

    let impact = apply_reputation_signal(&mut rec, ReputationSignal::Accepted);
    assert_eq!(impact.label, "accepted");
    assert_eq!(impact.delta, 3);
    assert_eq!(impact.tier, 3);
    assert_eq!(impact.weight_bps, 10_000);
    assert_eq!(impact.score_bps, 10_000);
    assert_eq!(impact.rank_ordinal, 0);
    assert_eq!(rec.reputation_delta, Some(3));
}

#[test]
fn canonical_reputation_surfaces_keep_all_score_axes_unique_per_signal() {
    let surfaces = canonical_reputation_surfaces();

    for (idx, surface) in surfaces.iter().enumerate() {
        for other in surfaces.iter().skip(idx + 1) {
            assert_ne!(surface.label, other.label);
            assert_ne!(surface.delta, other.delta);
            assert_ne!(surface.tier, other.tier);
            assert_ne!(surface.weight_bps, other.weight_bps);
            assert_ne!(surface.rank_ordinal, other.rank_ordinal);
        }
    }
}

#[test]
fn canonical_reputation_surfaces_form_a_strictly_descending_score_ladder() {
    let surfaces = canonical_reputation_surfaces();

    for window in surfaces.windows(2) {
        let current = window[0];
        let next = window[1];
        assert!(
            current.delta > next.delta,
            "score deltas must stay strictly descending across canonical surfaces"
        );
        assert!(
            current.tier > next.tier,
            "tiers must stay strictly descending across canonical surfaces"
        );
        assert!(
            current.weight_bps > next.weight_bps,
            "weight_bps must stay strictly descending across canonical surfaces"
        );
        assert_eq!(
            current.rank_ordinal + 1,
            next.rank_ordinal,
            "rank ordinals must remain dense and consecutive"
        );
    }
}
