use super::*;
use trnm_node_boundary_v0::ReferenceAuthorityCoordinatorV0;

fn digest(byte: u8) -> Digest32V0 {
    Digest32V0([byte; 32])
}

fn identity() -> NodeIdentityV0 {
    NodeIdentityV0 {
        chain_id: digest(1),
        validator_id: digest(2),
        application_id: digest(3),
        generation: 1,
    }
}

fn binding(height: u64, block: u8, parent: u8) -> OperationBindingV0 {
    OperationBindingV0::derive(
        identity(),
        height,
        height,
        digest(block),
        digest(parent),
        digest(block.wrapping_add(40)),
        digest(block.wrapping_add(80)),
        digest(block.wrapping_add(120)),
    )
    .unwrap()
}

fn new_session(
    coordinator: ReferenceAuthorityCoordinatorV0,
) -> ProductionAuthoritySessionV0<
    ReferenceAuthorityCoordinatorV0,
    fn(&ReferenceAuthorityCoordinatorV0) -> Option<AuthorityReceiptV0>,
> {
    ProductionAuthoritySessionV0::new(coordinator, ReferenceAuthorityCoordinatorV0::current)
        .unwrap()
}

#[test]
fn full_stage_chain_recovers_and_starts_parent_bound_successor() {
    let mut session = new_session(ReferenceAuthorityCoordinatorV0::new(identity()));
    assert_eq!(
        session.recover().unwrap(),
        AuthoritySessionReadinessV0::Ready
    );

    let first = binding(1, 10, 9);
    let mut receipt = session.begin_prepared(first, digest(20)).unwrap();
    assert_eq!(receipt.durable_stage, AuthorityStageV0::Prepared);
    assert_eq!(receipt.durable_sequence, 0);

    let successors = [
        AuthorityStageV0::ApplicationSealed,
        AuthorityStageV0::SafetyPersisted,
        AuthorityStageV0::SignIntentPersisted,
        AuthorityStageV0::SignatureConfirmed,
        AuthorityStageV0::FinalityApplied,
        AuthorityStageV0::CheckpointConfirmed,
        AuthorityStageV0::OutboundPublished,
    ];
    for (index, next) in successors.into_iter().enumerate() {
        let prior = receipt;
        receipt = session
            .advance(
                first,
                prior.durable_stage,
                next,
                digest(30 + u8::try_from(index).unwrap()),
            )
            .unwrap();
        assert_eq!(receipt.durable_sequence, prior.durable_sequence + 1);
        assert_ne!(receipt.record_digest, prior.record_digest);
    }

    let terminal = receipt;
    let coordinator = session.into_coordinator();
    let mut resumed = new_session(coordinator);
    assert_eq!(
        resumed.recover().unwrap(),
        AuthoritySessionReadinessV0::Ready
    );
    assert_eq!(resumed.current_receipt(), Some(terminal));

    let second = binding(2, 11, 10);
    let next = resumed.begin_prepared(second, digest(60)).unwrap();
    assert_eq!(next.durable_stage, AuthorityStageV0::Prepared);
    assert_eq!(next.durable_sequence, terminal.durable_sequence + 1);
    assert_ne!(next.record_digest, terminal.record_digest);
}

#[test]
fn resumed_summary_without_complete_receipt_stays_fenced() {
    let first = binding(1, 10, 9);
    let mut coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
    coordinator
        .apply(AuthorityCommandV0::Begin {
            binding: first,
            ingress_digest: digest(20),
        })
        .unwrap();
    let mut session = ProductionAuthoritySessionV0::new(coordinator, |_| None).unwrap();
    let error = session.recover().unwrap_err();
    assert!(matches!(
        error,
        AuthoritySessionErrorV0::Boundary(BoundaryErrorV0::ReceiptSubstitution)
    ));
    assert_eq!(session.readiness(), AuthoritySessionReadinessV0::Recovering);
    assert_eq!(session.current_receipt(), None);
}

struct LoseOneAcknowledgement {
    inner: ReferenceAuthorityCoordinatorV0,
    lose_next: bool,
}

impl AuthorityCoordinatorV0 for LoseOneAcknowledgement {
    type Error = BoundaryErrorV0;

    fn identity(&self) -> NodeIdentityV0 {
        self.inner.identity()
    }

    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
        self.inner.recover()
    }

    fn apply(&mut self, command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error> {
        let receipt = self.inner.apply(command)?;
        if self.lose_next {
            self.lose_next = false;
            return Err(BoundaryErrorV0::ReceiptSubstitution);
        }
        Ok(receipt)
    }
}

#[test]
fn lost_acknowledgement_requires_recovery_then_exact_replay() {
    let coordinator = LoseOneAcknowledgement {
        inner: ReferenceAuthorityCoordinatorV0::new(identity()),
        lose_next: true,
    };
    let mut session = ProductionAuthoritySessionV0::new(coordinator, |coordinator| {
        coordinator.inner.current()
    })
    .unwrap();
    session.recover().unwrap();
    let first = binding(1, 10, 9);
    assert!(matches!(
        session.begin_prepared(first, digest(20)),
        Err(AuthoritySessionErrorV0::Coordinator(
            BoundaryErrorV0::ReceiptSubstitution
        ))
    ));
    assert_eq!(session.readiness(), AuthoritySessionReadinessV0::Recovering);
    assert_eq!(session.current_receipt(), None);

    session.recover().unwrap();
    let recovered = session.current_receipt().unwrap();
    let replayed = session.begin_prepared(first, digest(20)).unwrap();
    assert_eq!(replayed, recovered);
}

#[test]
fn substituted_post_write_readback_revokes_readiness() {
    let coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
    let mut session = ProductionAuthoritySessionV0::new(coordinator, |coordinator| {
        coordinator.current().map(|mut receipt| {
            receipt.facts_digest = digest(250);
            receipt
        })
    })
    .unwrap();
    session.recover().unwrap();
    let error = session
        .begin_prepared(binding(1, 10, 9), digest(20))
        .unwrap_err();
    assert!(matches!(
        error,
        AuthoritySessionErrorV0::Boundary(BoundaryErrorV0::ReceiptSubstitution)
    ));
    assert_eq!(session.readiness(), AuthoritySessionReadinessV0::Recovering);
    assert_eq!(session.current_receipt(), None);
}

#[test]
fn skip_and_reordered_stage_are_rejected_without_mutation() {
    let mut session = new_session(ReferenceAuthorityCoordinatorV0::new(identity()));
    session.recover().unwrap();
    let first = binding(1, 10, 9);
    let prepared = session.begin_prepared(first, digest(20)).unwrap();

    let error = session
        .advance(
            first,
            AuthorityStageV0::Prepared,
            AuthorityStageV0::SafetyPersisted,
            digest(21),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        AuthoritySessionErrorV0::Boundary(BoundaryErrorV0::InvalidStageTransition)
    ));
    assert_eq!(session.current_receipt(), Some(prepared));
    assert_eq!(session.coordinator().current(), Some(prepared));
}

#[test]
fn same_stage_replay_requires_the_exact_facts_and_receipt() {
    let mut session = new_session(ReferenceAuthorityCoordinatorV0::new(identity()));
    session.recover().unwrap();
    let first = binding(1, 10, 9);
    session.begin_prepared(first, digest(20)).unwrap();
    let sealed = session
        .advance(
            first,
            AuthorityStageV0::Prepared,
            AuthorityStageV0::ApplicationSealed,
            digest(21),
        )
        .unwrap();
    let replay = session
        .advance(
            first,
            AuthorityStageV0::Prepared,
            AuthorityStageV0::ApplicationSealed,
            digest(21),
        )
        .unwrap();
    assert_eq!(replay, sealed);

    let error = session
        .advance(
            first,
            AuthorityStageV0::Prepared,
            AuthorityStageV0::ApplicationSealed,
            digest(22),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        AuthoritySessionErrorV0::Boundary(BoundaryErrorV0::ReceiptSubstitution)
    ));
    assert_eq!(session.current_receipt(), Some(sealed));
}

struct QuarantinedCoordinator;

impl AuthorityCoordinatorV0 for QuarantinedCoordinator {
    type Error = BoundaryErrorV0;

    fn identity(&self) -> NodeIdentityV0 {
        identity()
    }

    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
        Ok(RecoveryDispositionV0::Quarantine {
            reason_digest: digest(200),
        })
    }

    fn apply(&mut self, _command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error> {
        Err(BoundaryErrorV0::InvalidStageTransition)
    }
}

#[test]
fn quarantine_never_grants_write_readiness() {
    let mut session = ProductionAuthoritySessionV0::new(QuarantinedCoordinator, |_| None).unwrap();
    assert_eq!(
        session.recover().unwrap(),
        AuthoritySessionReadinessV0::Quarantined(digest(200))
    );
    assert!(matches!(
        session.begin_prepared(binding(1, 10, 9), digest(20)),
        Err(AuthoritySessionErrorV0::NotReady)
    ));
}

struct FalseCleanCoordinator {
    inner: ReferenceAuthorityCoordinatorV0,
}

impl AuthorityCoordinatorV0 for FalseCleanCoordinator {
    type Error = BoundaryErrorV0;

    fn identity(&self) -> NodeIdentityV0 {
        self.inner.identity()
    }

    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
        Ok(RecoveryDispositionV0::Clean)
    }

    fn apply(&mut self, command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error> {
        self.inner.apply(command)
    }
}

#[test]
fn clean_summary_with_retained_receipt_is_inconsistent() {
    let first = binding(1, 10, 9);
    let mut inner = ReferenceAuthorityCoordinatorV0::new(identity());
    inner
        .apply(AuthorityCommandV0::Begin {
            binding: first,
            ingress_digest: digest(20),
        })
        .unwrap();
    let coordinator = FalseCleanCoordinator { inner };
    let mut session = ProductionAuthoritySessionV0::new(coordinator, |coordinator| {
        coordinator.inner.current()
    })
    .unwrap();
    let error = session.recover().unwrap_err();
    assert!(matches!(
        error,
        AuthoritySessionErrorV0::Boundary(BoundaryErrorV0::ReceiptSubstitution)
    ));
    assert_eq!(session.readiness(), AuthoritySessionReadinessV0::Recovering);
}
