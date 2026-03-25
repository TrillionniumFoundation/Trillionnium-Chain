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
    assert_eq!(rec.reputation_delta, Some(-2));

    let impact = apply_reputation_signal(&mut rec, ReputationSignal::Accepted);
    assert_eq!(impact.label, "accepted");
    assert_eq!(impact.delta, 3);
    assert_eq!(impact.tier, 3);
    assert_eq!(rec.reputation_delta, Some(3));
}
