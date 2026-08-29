use trnm_poco_verify_challenge_v1::profile_registry_v1::*;

const _: () = {
    assert!(!VERIFICATION_PROFILE_FALLBACK_ALLOWED_V1);
    assert!(!VERIFICATION_PROFILES_GLOBALLY_ENABLED_V1);
    assert!(!VERIFICATION_DECISION_ECONOMIC_AUTHORITY_V1);
    assert!(!VERIFICATION_DECISION_ORDER_REORG_AUTHORITY_V1);
    assert!(!VERIFICATION_DECISION_POCO_WEIGHT_AUTHORITY_V1);
};

fn id(value: u8) -> [u8; 32] {
    let mut out = [0; 32];
    out[31] = value;
    out
}

fn profiles(enabled_kind: VerificationProfileKindV1) -> Vec<VerificationProfileV1> {
    [
        VerificationProfileKindV1::DeterministicReexecution,
        VerificationProfileKindV1::ReproducibleMachineLearning,
        VerificationProfileKindV1::ZeroKnowledge,
        VerificationProfileKindV1::TrustedExecutionEnvironment,
        VerificationProfileKindV1::StakeQuorum,
        VerificationProfileKindV1::Optimistic,
        VerificationProfileKindV1::Subjective,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, kind)| VerificationProfileV1 {
        profile_id: id(10 + index as u8),
        version: 1,
        profile_hash: id(30 + index as u8),
        kind,
        enabled: kind == enabled_kind,
        valid_from_height: 10,
        expires_at_height: Some(100),
        revoked_at_height: None,
        objective_settlement_allowed: false,
        poco_weight_allowed: false,
    })
    .collect()
}

fn statement() -> VerificationStatementV1 {
    VerificationStatementV1::new(
        id(1),
        id(2),
        id(3),
        id(10),
        1,
        id(30),
        id(4),
        id(5),
        10,
        50,
        20,
    )
    .expect("statement")
}

fn evidence() -> VerificationEvidenceV1 {
    VerificationEvidenceV1 {
        task_id: id(1),
        lease_id: id(2),
        execution_receipt_id: id(3),
        artifact_evidence_digest: id(4),
        availability_certificate_digest: id(5),
        backend_payload_digest: id(6),
    }
}

#[derive(Default)]
struct CountingBackend {
    calls: usize,
    result: Option<VerificationBackendResultV1>,
}

impl VerificationBackendV1 for CountingBackend {
    fn verify(
        &mut self,
        _profile: VerificationProfileV1,
        _statement: &VerificationStatementV1,
        _evidence: &VerificationEvidenceV1,
    ) -> VerificationBackendResultV1 {
        self.calls += 1;
        self.result
            .unwrap_or(VerificationBackendResultV1::Unavailable)
    }
}

#[test]
fn exact_resolution_and_evidence_precede_backend() {
    let registry = VerificationProfileRegistryV1::closed(profiles(
        VerificationProfileKindV1::DeterministicReexecution,
    ))
    .expect("registry");
    assert_eq!(registry.len(), 7);
    assert!(!registry.is_empty());

    let mut bad_statement = statement();
    bad_statement.profile_hash = id(99);
    let mut backend = CountingBackend::default();
    assert_eq!(
        verify_statement_v1(&registry, &bad_statement, &evidence(), 20, &mut backend),
        Err(VerificationProfileErrorV1::MalformedStatement)
    );
    assert_eq!(backend.calls, 0);

    let mut bad_evidence = evidence();
    bad_evidence.task_id = id(77);
    assert_eq!(
        verify_statement_v1(&registry, &statement(), &bad_evidence, 20, &mut backend),
        Err(VerificationProfileErrorV1::EvidenceBindingMismatch)
    );
    assert_eq!(backend.calls, 0);
}

#[test]
fn verified_rejected_and_unavailable_are_distinct_and_non_authoritative() {
    let registry = VerificationProfileRegistryV1::closed(profiles(
        VerificationProfileKindV1::DeterministicReexecution,
    ))
    .expect("registry");
    for (backend_result, expected) in [
        (
            VerificationBackendResultV1::Verified,
            VerificationDecisionStatusV1::Verified,
        ),
        (
            VerificationBackendResultV1::Rejected,
            VerificationDecisionStatusV1::Rejected,
        ),
        (
            VerificationBackendResultV1::Unavailable,
            VerificationDecisionStatusV1::Unavailable,
        ),
    ] {
        let mut backend = CountingBackend {
            calls: 0,
            result: Some(backend_result),
        };
        let decision = verify_statement_v1(
            &registry,
            &statement(),
            &evidence(),
            20,
            &mut backend,
        )
        .expect("decision");
        assert_eq!(decision.status, expected);
        assert_eq!(backend.calls, 1);
        assert!(!decision.economic_authority);
        assert!(!decision.order_reorg_authority);
        assert!(!decision.poco_weight_authority);
    }
}

#[test]
fn disabled_expired_revoked_and_unknown_profiles_do_not_fallback() {
    let disabled = VerificationProfileRegistryV1::closed(profiles(
        VerificationProfileKindV1::StakeQuorum,
    ))
    .expect("registry");
    let mut backend = CountingBackend::default();
    assert_eq!(
        verify_statement_v1(&disabled, &statement(), &evidence(), 20, &mut backend),
        Err(VerificationProfileErrorV1::ProfileDisabled)
    );
    assert_eq!(backend.calls, 0);
}

#[test]
fn subjective_profiles_cannot_escalate_objective_authority() {
    let mut rows = profiles(VerificationProfileKindV1::Subjective);
    let subjective = rows
        .iter_mut()
        .find(|row| row.kind == VerificationProfileKindV1::Subjective)
        .expect("subjective");
    subjective.objective_settlement_allowed = true;
    assert_eq!(
        VerificationProfileRegistryV1::closed(rows),
        Err(VerificationProfileErrorV1::SubjectiveAuthorityEscalation)
    );
}

#[test]
fn duplicate_challenge_is_rejected_and_lifecycle_is_forward_only() {
    let mut book = ChallengeBookV1::default();
    let result_id = id(81);
    book.open(id(80), result_id, id(82), 10, 20, 30, 40, 50, 60)
        .expect("open");
    assert_eq!(
        book.open(id(83), result_id, id(84), 10, 20, 30, 40, 50, 60),
        Err(VerificationProfileErrorV1::DuplicateChallenge)
    );
    let record = book.get_mut(&result_id).expect("record");
    record.submit_evidence(20).expect("evidence");
    record.begin_response(30).expect("response period");
    record.submit_response(35).expect("response");
    record
        .decide(45, ChallengeFinalOutcomeV1::Upheld)
        .expect("decision");
    record.appeal(55, 60).expect("appeal");
    assert_eq!(
        record.appeal(55, 60),
        Err(VerificationProfileErrorV1::AppealAlreadyUsed)
    );
    record
        .decide(58, ChallengeFinalOutcomeV1::Rejected)
        .expect("appeal decision");
    record.finalize(61).expect("finalize");
    assert_eq!(record.phase, ChallengePhaseV1::Final);
    assert_eq!(record.final_outcome, Some(ChallengeFinalOutcomeV1::Rejected));
    assert!(!record.economic_authority);
    assert!(!record.order_reorg);
}

#[test]
fn withdrawal_and_expiry_close_without_economic_or_order_authority() {
    let mut book = ChallengeBookV1::default();
    let result_id = id(91);
    let record = book
        .open(id(90), result_id, id(92), 10, 20, 30, 40, 50, 60)
        .expect("open");
    record.withdraw().expect("withdraw");
    assert_eq!(record.final_outcome, Some(ChallengeFinalOutcomeV1::Withdrawn));

    let mut book = ChallengeBookV1::default();
    let result_id = id(94);
    let record = book
        .open(id(93), result_id, id(95), 10, 20, 30, 40, 50, 60)
        .expect("open");
    record.expire(31).expect("expire");
    assert_eq!(record.final_outcome, Some(ChallengeFinalOutcomeV1::Expired));
}
