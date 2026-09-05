//! Exercise exact recovery and monotonic host-owned authority progression.
use super::*;
use std::{cell::Cell, error::Error, fmt, rc::Rc};

fn digest(byte: u8) -> Digest32V0 {
    Digest32V0([byte; 32])
}

fn identity() -> NodeIdentityV0 {
    NodeIdentityV0 {
        chain_id: digest(1),
        validator_id: digest(2),
        application_id: digest(3),
        generation: 4,
    }
}

fn ingress(height: u64, block: u8, parent: u8, nonce: u64) -> BoundIngressV0 {
    BoundIngressV0::derive(
        identity(),
        height,
        height + 10,
        digest(block),
        digest(parent),
        IngressFrameV0::new(digest(5), digest(6), nonce, vec![block, parent]).unwrap(),
    )
    .unwrap()
}

#[derive(Default)]
struct IdleIo;

impl IoRuntimeV0 for IdleIo {
    type Error = BoundaryErrorV0;

    fn poll_ingress(&mut self, _budget: StepBudgetV0) -> Result<IoPollV0, Self::Error> {
        Ok(IoPollV0::Idle)
    }

    fn publish(
        &mut self,
        _frame: OutboundFrameV0,
        _budget: StepBudgetV0,
    ) -> Result<(), Self::Error> {
        Err(BoundaryErrorV0::InvalidStageTransition)
    }
}

fn stages() -> [AuthorityStageV0; 7] {
    [
        AuthorityStageV0::ApplicationSealed,
        AuthorityStageV0::SafetyPersisted,
        AuthorityStageV0::SignIntentPersisted,
        AuthorityStageV0::SignatureConfirmed,
        AuthorityStageV0::FinalityApplied,
        AuthorityStageV0::CheckpointConfirmed,
        AuthorityStageV0::OutboundPublished,
    ]
}

#[test]
fn host_advances_the_exact_chain_and_resumes_the_complete_receipt() {
    let coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
    let mut host =
        PersistentValidatorHostV0::new(coordinator, IdleIo, StepBudgetV0::default()).unwrap();
    assert_eq!(host.recover().unwrap(), HostReadinessV0::Ready);
    assert_eq!(host.current_receipt(), None);

    let first_ingress = ingress(1, 10, 9, 1);
    let mut previous = host.prepare_bound_ingress(&first_ingress).unwrap();
    assert_eq!(previous.durable_sequence, 0);
    assert_eq!(previous.previous_record_digest, Digest32V0([0; 32]));
    assert_eq!(host.current_receipt(), Some(previous));

    for (index, next_stage) in stages().into_iter().enumerate() {
        let facts = digest(20 + u8::try_from(index).unwrap());
        let current = host.advance_authority(next_stage, facts).unwrap();
        assert_eq!(current.binding, previous.binding);
        assert_eq!(current.durable_stage, next_stage);
        assert_eq!(current.durable_sequence, previous.durable_sequence + 1);
        assert_eq!(current.facts_digest, facts);
        assert_eq!(current.previous_record_digest, previous.record_digest);
        assert_eq!(host.current_receipt(), Some(current));
        previous = current;
    }
    assert_eq!(previous.durable_sequence, 7);

    let (coordinator, io) = host.into_parts();
    let mut restarted =
        PersistentValidatorHostV0::new(coordinator, io, StepBudgetV0::default()).unwrap();
    assert_eq!(restarted.recover().unwrap(), HostReadinessV0::Ready);
    assert_eq!(restarted.current_receipt(), Some(previous));
    assert_eq!(
        restarted
            .advance_authority(previous.durable_stage, previous.facts_digest)
            .unwrap(),
        previous
    );

    let second_ingress = ingress(2, 11, 10, 2);
    let prepared = restarted.prepare_bound_ingress(&second_ingress).unwrap();
    assert_eq!(prepared.durable_sequence, 8);
    assert_eq!(prepared.previous_record_digest, previous.record_digest);
    assert_eq!(prepared.binding.parent_id, previous.binding.block_id);
}

struct SummaryOnlyCoordinator {
    identity: NodeIdentityV0,
    receipt: AuthorityReceiptV0,
}

impl AuthorityCoordinatorV0 for SummaryOnlyCoordinator {
    type Error = BoundaryErrorV0;

    fn identity(&self) -> NodeIdentityV0 {
        self.identity
    }

    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
        Ok(RecoveryDispositionV0::Resume {
            binding: self.receipt.binding,
            durable_stage: self.receipt.durable_stage,
            durable_sequence: self.receipt.durable_sequence,
        })
    }

    fn apply(&mut self, _command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error> {
        Err(BoundaryErrorV0::IncompleteRecoveryReceipt)
    }
}

#[test]
fn summary_only_recovery_cannot_restore_mutation_authority() {
    let mut reference = ReferenceAuthorityCoordinatorV0::new(identity());
    let receipt = reference
        .apply(AuthorityCommandV0::Begin {
            binding: ingress(1, 10, 9, 1).binding,
            ingress_digest: digest(30),
        })
        .unwrap();
    let coordinator = SummaryOnlyCoordinator {
        identity: identity(),
        receipt,
    };
    let mut host =
        PersistentValidatorHostV0::new(coordinator, IdleIo, StepBudgetV0::default()).unwrap();
    assert!(matches!(
        host.recover(),
        Err(HostErrorV0::Boundary(
            BoundaryErrorV0::IncompleteRecoveryReceipt
        ))
    ));
    assert_eq!(host.current_receipt(), None);
    assert_eq!(host.readiness(), HostReadinessV0::Recovering);
    assert!(matches!(host.step(), Err(HostErrorV0::NotReady)));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestError {
    Boundary(BoundaryErrorV0),
    LostAcknowledgement,
}

impl fmt::Display for TestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary(error) => write!(f, "{error}"),
            Self::LostAcknowledgement => f.write_str("injected lost acknowledgement"),
        }
    }
}

impl Error for TestError {}

struct LostAckCoordinator {
    inner: ReferenceAuthorityCoordinatorV0,
    fail_next_advance: Rc<Cell<bool>>,
    apply_count: Rc<Cell<usize>>,
}

impl AuthorityCoordinatorV0 for LostAckCoordinator {
    type Error = TestError;

    fn identity(&self) -> NodeIdentityV0 {
        self.inner.identity()
    }

    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
        self.inner.recover().map_err(TestError::Boundary)
    }

    fn apply(&mut self, command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error> {
        self.apply_count.set(self.apply_count.get() + 1);
        let is_advance = matches!(&command, AuthorityCommandV0::Advance { .. });
        let receipt = self.inner.apply(command).map_err(TestError::Boundary)?;
        if is_advance && self.fail_next_advance.replace(false) {
            return Err(TestError::LostAcknowledgement);
        }
        Ok(receipt)
    }
}

#[test]
fn lost_advance_acknowledgement_recovers_and_replays_without_another_write() {
    let fail = Rc::new(Cell::new(false));
    let applies = Rc::new(Cell::new(0));
    let coordinator = LostAckCoordinator {
        inner: ReferenceAuthorityCoordinatorV0::new(identity()),
        fail_next_advance: Rc::clone(&fail),
        apply_count: Rc::clone(&applies),
    };
    let mut host =
        PersistentValidatorHostV0::new(coordinator, IdleIo, StepBudgetV0::default()).unwrap();
    host.recover().unwrap();
    let prepared = host.prepare_bound_ingress(&ingress(1, 10, 9, 1)).unwrap();
    fail.set(true);
    assert!(matches!(
        host.advance_authority(AuthorityStageV0::ApplicationSealed, digest(40)),
        Err(HostErrorV0::Coordinator(TestError::LostAcknowledgement))
    ));
    assert_eq!(host.current_receipt(), None);
    assert_eq!(host.readiness(), HostReadinessV0::Recovering);

    host.recover().unwrap();
    let recovered = host.current_receipt().unwrap();
    assert_eq!(recovered.durable_stage, AuthorityStageV0::ApplicationSealed);
    assert_eq!(recovered.previous_record_digest, prepared.record_digest);
    let before = applies.get();
    assert_eq!(
        host.advance_authority(AuthorityStageV0::ApplicationSealed, digest(40))
            .unwrap(),
        recovered
    );
    assert_eq!(applies.get(), before);
}

#[derive(Clone, Copy)]
enum ReceiptFault {
    Binding,
    Stage,
    Sequence,
    Facts,
    Previous,
    Record,
}

struct SubstitutingCoordinator {
    inner: ReferenceAuthorityCoordinatorV0,
    fault: Rc<Cell<Option<ReceiptFault>>>,
}

impl AuthorityCoordinatorV0 for SubstitutingCoordinator {
    type Error = BoundaryErrorV0;

    fn identity(&self) -> NodeIdentityV0 {
        self.inner.identity()
    }

    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
        self.inner.recover()
    }

    fn apply(&mut self, command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error> {
        let mut receipt = self.inner.apply(command)?;
        if let Some(fault) = self.fault.take() {
            match fault {
                ReceiptFault::Binding => receipt.binding.operation_id = digest(90),
                ReceiptFault::Stage => receipt.durable_stage = AuthorityStageV0::FinalityApplied,
                ReceiptFault::Sequence => receipt.durable_sequence += 1,
                ReceiptFault::Facts => receipt.facts_digest = digest(91),
                ReceiptFault::Previous => receipt.previous_record_digest = Digest32V0([0; 32]),
                ReceiptFault::Record => receipt.record_digest = Digest32V0([0; 32]),
            }
        }
        Ok(receipt)
    }
}

#[test]
fn every_advanced_receipt_field_is_revalidated_and_uncertainty_is_fenced() {
    for fault in [
        ReceiptFault::Binding,
        ReceiptFault::Stage,
        ReceiptFault::Sequence,
        ReceiptFault::Facts,
        ReceiptFault::Previous,
        ReceiptFault::Record,
    ] {
        let control = Rc::new(Cell::new(None));
        let coordinator = SubstitutingCoordinator {
            inner: ReferenceAuthorityCoordinatorV0::new(identity()),
            fault: Rc::clone(&control),
        };
        let mut host = PersistentValidatorHostV0::new(
            coordinator,
            IdleIo,
            StepBudgetV0::default(),
        )
        .unwrap();
        host.recover().unwrap();
        host.prepare_bound_ingress(&ingress(1, 10, 9, 1)).unwrap();
        control.set(Some(fault));
        assert!(host
            .advance_authority(AuthorityStageV0::ApplicationSealed, digest(50))
            .is_err());
        assert_eq!(host.current_receipt(), None);
        assert_eq!(host.readiness(), HostReadinessV0::Recovering);
        assert!(matches!(host.step(), Err(HostErrorV0::NotReady)));

        host.recover().unwrap();
        let exact = host.current_receipt().unwrap();
        assert_eq!(exact.durable_stage, AuthorityStageV0::ApplicationSealed);
        assert_eq!(
            host.advance_authority(AuthorityStageV0::ApplicationSealed, digest(50))
                .unwrap(),
            exact
        );
    }
}

#[test]
fn invalid_advance_requests_do_not_discard_a_known_durable_receipt() {
    let coordinator = ReferenceAuthorityCoordinatorV0::new(identity());
    let mut host =
        PersistentValidatorHostV0::new(coordinator, IdleIo, StepBudgetV0::default()).unwrap();
    host.recover().unwrap();
    let prepared = host.prepare_bound_ingress(&ingress(1, 10, 9, 1)).unwrap();

    for (stage, facts, expected) in [
        (
            AuthorityStageV0::Prepared,
            prepared.facts_digest,
            BoundaryErrorV0::InvalidStageTransition,
        ),
        (
            AuthorityStageV0::ApplicationSealed,
            Digest32V0([0; 32]),
            BoundaryErrorV0::ReceiptSubstitution,
        ),
        (
            AuthorityStageV0::SignatureConfirmed,
            digest(60),
            BoundaryErrorV0::InvalidStageTransition,
        ),
    ] {
        assert!(matches!(
            host.advance_authority(stage, facts),
            Err(HostErrorV0::Boundary(error)) if error == expected
        ));
        assert_eq!(host.readiness(), HostReadinessV0::Ready);
        assert_eq!(host.current_receipt(), Some(prepared));
    }
}

struct ExactRecoveryCoordinator {
    receipt: AuthorityReceiptV0,
}

impl AuthorityCoordinatorV0 for ExactRecoveryCoordinator {
    type Error = BoundaryErrorV0;

    fn identity(&self) -> NodeIdentityV0 {
        identity()
    }

    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
        Ok(RecoveryDispositionV0::ResumeExact {
            receipt: self.receipt,
        })
    }

    fn apply(&mut self, _command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error> {
        Err(BoundaryErrorV0::InvalidStageTransition)
    }
}

#[test]
fn malformed_exact_recovery_receipts_never_restore_readiness() {
    let binding = ingress(1, 10, 9, 1).binding;
    let base = AuthorityReceiptV0 {
        binding,
        durable_stage: AuthorityStageV0::ApplicationSealed,
        durable_sequence: 1,
        facts_digest: digest(70),
        previous_record_digest: digest(71),
        record_digest: digest(72),
    };
    let mut cases = Vec::new();
    let mut zero_previous = base;
    zero_previous.previous_record_digest = Digest32V0([0; 32]);
    cases.push(zero_previous);
    let mut zero_facts = base;
    zero_facts.facts_digest = Digest32V0([0; 32]);
    cases.push(zero_facts);
    let mut zero_record = base;
    zero_record.record_digest = Digest32V0([0; 32]);
    cases.push(zero_record);
    let mut first_with_previous = base;
    first_with_previous.durable_sequence = 0;
    cases.push(first_with_previous);

    for receipt in cases {
        let coordinator = ExactRecoveryCoordinator { receipt };
        let mut host = PersistentValidatorHostV0::new(
            coordinator,
            IdleIo,
            StepBudgetV0::default(),
        )
        .unwrap();
        assert!(matches!(
            host.recover(),
            Err(HostErrorV0::Boundary(
                BoundaryErrorV0::ReceiptSubstitution
            ))
        ));
        assert_eq!(host.current_receipt(), None);
        assert_eq!(host.readiness(), HostReadinessV0::Recovering);
    }
}
