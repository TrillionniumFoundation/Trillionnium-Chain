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
