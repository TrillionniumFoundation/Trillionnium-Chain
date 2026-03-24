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
