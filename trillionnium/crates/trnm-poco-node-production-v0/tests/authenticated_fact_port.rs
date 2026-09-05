use std::convert::Infallible;

use trnm_node_boundary_v0::{
    AuthorityReceiptV0, AuthorityStageV0, BoundaryErrorV0, Digest32V0, NodeIdentityV0,
    OperationBindingV0, ReferenceAuthorityCoordinatorV0,
};
use trnm_poco_node_production_v0::{
    AuthorityFactClaimV0, AuthorityFactSourceV0, AuthorityFactVerificationErrorV0,
    AuthoritySessionErrorV0, AuthoritySessionReadinessV0, ProductionAuthoritySessionV0,
};

fn d(byte: u8) -> Digest32V0 {
    Digest32V0([byte; 32])
}

fn identity() -> NodeIdentityV0 {
    NodeIdentityV0 {
        chain_id: d(1),
        validator_id: d(2),
        application_id: d(3),
        generation: 1,
    }
}

fn binding(height: u64, block: u8, parent: u8) -> OperationBindingV0 {
    OperationBindingV0::derive(
        identity(),
        height,
        height,
        d(block),
        d(parent),
        d(block.wrapping_add(40)),
    )
}

type Session = ProductionAuthoritySessionV0<
    ReferenceAuthorityCoordinatorV0,
    fn(&ReferenceAuthorityCoordinatorV0) -> Option<AuthorityReceiptV0>,
>;

fn session() -> Session {
    let coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
    let mut session =
        ProductionAuthoritySessionV0::new(coordinator, ReferenceAuthorityCoordinatorV0::current)
            .unwrap();
    assert_eq!(
        session.recover().unwrap(),
        AuthoritySessionReadinessV0::Ready
    );
    session
}

fn claim(
    operation: OperationBindingV0,
    stage: AuthorityStageV0,
    payload: u8,
) -> AuthorityFactClaimV0 {
    AuthorityFactClaimV0::new(
        identity(),
        operation,
        stage,
        d(100u8.wrapping_add(stage as u8)),
        u64::from(stage as u8) + 1,
        d(payload),
    )
    .unwrap()
}

#[derive(Default)]
struct CountingSource {
    calls: usize,
}

impl AuthorityFactSourceV0 for CountingSource {
    type Error = Infallible;

    fn verify_fact(
        &mut self,
        observed_identity: NodeIdentityV0,
        prior: AuthorityReceiptV0,
        observed_claim: &AuthorityFactClaimV0,
    ) -> Result<(), Self::Error> {
        assert_eq!(observed_identity, identity());
        assert_eq!(prior.binding, observed_claim.binding());
        self.calls += 1;
        Ok(())
    }
}

#[test]
fn claim_constructor_rejects_unbound_or_zero_authority_facts() {
    let operation = binding(1, 10, 9);
    for result in [
        AuthorityFactClaimV0::new(
            identity(),
            operation,
            AuthorityStageV0::Prepared,
            d(10),
            1,
            d(11),
        ),
        AuthorityFactClaimV0::new(
            identity(),
            operation,
            AuthorityStageV0::ApplicationSealed,
            d(0),
            1,
            d(11),
        ),
        AuthorityFactClaimV0::new(
            identity(),
            operation,
            AuthorityStageV0::ApplicationSealed,
            d(10),
            0,
            d(11),
        ),
        AuthorityFactClaimV0::new(
            identity(),
            operation,
            AuthorityStageV0::ApplicationSealed,
            d(10),
            1,
            d(0),
        ),
    ] {
        assert!(matches!(result, Err(BoundaryErrorV0::ReceiptSubstitution)));
    }

    let mut invalid = operation;
    invalid.block_id = d(0);
    assert!(matches!(
        AuthorityFactClaimV0::new(
            identity(),
            invalid,
            AuthorityStageV0::ApplicationSealed,
            d(10),
            1,
            d(11),
        ),
        Err(BoundaryErrorV0::InvalidOperationBinding)
    ));
}

#[test]
fn invalid_operation_and_stage_are_rejected_before_source_authority_is_called() {
    let mut session = session();
    let first = binding(1, 10, 9);
    let prepared = session.begin_prepared(first, d(20)).unwrap();
    let mut source = CountingSource::default();

    let wrong_operation = claim(
        binding(2, 11, 10),
        AuthorityStageV0::ApplicationSealed,
        21,
    );
    assert!(matches!(
        session.verify_fact(wrong_operation, &mut source),
        Err(AuthorityFactVerificationErrorV0::Boundary(
            BoundaryErrorV0::OperationBindingMismatch
        ))
    ));
    assert_eq!(source.calls, 0);

    let skipped = claim(first, AuthorityStageV0::SafetyPersisted, 22);
    assert!(matches!(
        session.verify_fact(skipped, &mut source),
        Err(AuthorityFactVerificationErrorV0::Boundary(
            BoundaryErrorV0::InvalidStageTransition
        ))
    ));
    assert_eq!(source.calls, 0);
    assert_eq!(session.current_receipt(), Some(prepared));
}

#[test]
fn token_is_bound_to_one_predecessor_and_exact_replay_claim() {
    let mut session = session();
    let first = binding(1, 10, 9);
    session.begin_prepared(first, d(20)).unwrap();
    let exact = claim(first, AuthorityStageV0::ApplicationSealed, 21);
    let mut source = CountingSource::default();
    let accepted = session.verify_fact(exact.clone(), &mut source).unwrap();
    let stale = session.verify_fact(exact.clone(), &mut source).unwrap();
    let sealed = session.advance_verified(accepted).unwrap();

    assert!(matches!(
        session.advance_verified(stale),
        Err(AuthoritySessionErrorV0::Boundary(
            BoundaryErrorV0::ReceiptSubstitution
        ))
    ));
    assert_eq!(session.current_receipt(), Some(sealed));

    let replay = session.verify_fact(exact, &mut source).unwrap();
    assert_eq!(session.advance_verified(replay).unwrap(), sealed);
    assert!(matches!(
        session.verify_fact(
            claim(first, AuthorityStageV0::ApplicationSealed, 22),
            &mut source,
        ),
        Err(AuthorityFactVerificationErrorV0::Boundary(
            BoundaryErrorV0::ReceiptSubstitution
        ))
    ));
}

#[derive(Debug, Eq, PartialEq)]
enum SourceError {
    Rejected,
}

struct RejectingSource;

impl AuthorityFactSourceV0 for RejectingSource {
    type Error = SourceError;

    fn verify_fact(
        &mut self,
        _identity: NodeIdentityV0,
        _prior: AuthorityReceiptV0,
        _claim: &AuthorityFactClaimV0,
    ) -> Result<(), Self::Error> {
        Err(SourceError::Rejected)
    }
}

#[test]
fn source_rejection_never_mutates_or_revokes_the_recovered_predecessor() {
    let mut session = session();
    let first = binding(1, 10, 9);
    let prepared = session.begin_prepared(first, d(20)).unwrap();
    let error = session
        .verify_fact(
            claim(first, AuthorityStageV0::ApplicationSealed, 21),
            &mut RejectingSource,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        AuthorityFactVerificationErrorV0::Source(SourceError::Rejected)
    ));
    assert_eq!(session.readiness(), AuthoritySessionReadinessV0::Ready);
    assert_eq!(session.current_receipt(), Some(prepared));
    assert_eq!(session.coordinator().current(), Some(prepared));
}
