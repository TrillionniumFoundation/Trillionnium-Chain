//! Exercise the real host with explicitly faulting, non-production adapters.
use super::*;
use std::{cell::Cell, panic::AssertUnwindSafe, rc::Rc};

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Error,
    AfterWrite,
    Panic,
    Binding,
    Stage,
    Facts,
    Record,
    Identity,
}

#[derive(Default)]
struct Controls {
    recovery: Cell<Fault>,
    apply: Cell<Fault>,
    polls: Cell<usize>,
    applies: Cell<usize>,
    io_error: Cell<bool>,
}

struct FaultCoordinator {
    inner: ReferenceAuthorityCoordinatorV0,
    identity: Rc<Cell<NodeIdentityV0>>,
    controls: Rc<Controls>,
}

impl AuthorityCoordinatorV0 for FaultCoordinator {
    type Error = BoundaryErrorV0;

    fn identity(&self) -> NodeIdentityV0 {
        self.identity.get()
    }

    fn recover(&mut self) -> Result<RecoveryDispositionV0, Self::Error> {
        match self.controls.recovery.replace(Fault::None) {
            Fault::Error => return Err(BoundaryErrorV0::ReceiptSubstitution),
            Fault::Panic => panic!("injected recovery panic"),
            Fault::Binding => {
                let mut binding = ingress().binding;
                binding.operation_id = Digest32V0([0; 32]);
                return Ok(RecoveryDispositionV0::Resume {
                    binding,
                    durable_stage: AuthorityStageV0::Prepared,
                    durable_sequence: 0,
                });
            }
            Fault::Identity => self.identity.set(other_identity()),
            _ => {}
        }
        self.inner.recover()
    }

    fn apply(&mut self, command: AuthorityCommandV0) -> Result<AuthorityReceiptV0, Self::Error> {
        self.controls.applies.set(self.controls.applies.get() + 1);
        let fault = self.controls.apply.replace(Fault::None);
        match fault {
            Fault::Error => return Err(BoundaryErrorV0::ReceiptSubstitution),
            Fault::Panic => panic!("injected apply panic"),
            _ => {}
        }
        let mut receipt = self.inner.apply(command)?;
        match fault {
            Fault::AfterWrite => return Err(BoundaryErrorV0::ReceiptSubstitution),
            Fault::Binding => receipt.binding.operation_id = Digest32V0([9; 32]),
            Fault::Stage => receipt.durable_stage = AuthorityStageV0::SignatureConfirmed,
            Fault::Facts => receipt.facts_digest = Digest32V0([9; 32]),
            Fault::Record => receipt.record_digest = Digest32V0([0; 32]),
            Fault::Identity => self.identity.set(other_identity()),
            _ => {}
        }
        Ok(receipt)
    }
}

struct ObservedIo(Rc<Controls>);
impl IoRuntimeV0 for ObservedIo {
    type Error = BoundaryErrorV0;

    fn poll_ingress(&mut self, _budget: StepBudgetV0) -> Result<IoPollV0, Self::Error> {
        self.0.polls.set(self.0.polls.get() + 1);
        if self.0.io_error.replace(false) {
            return Err(BoundaryErrorV0::BudgetExceeded);
        }
        Ok(IoPollV0::Idle)
    }

    fn publish(
        &mut self,
        _frame: OutboundFrameV0,
        _budget: StepBudgetV0,
    ) -> Result<(), Self::Error> {
        panic!("these host operations must not publish")
    }
}

type Host = PersistentValidatorHostV0<FaultCoordinator, ObservedIo>;

fn identity() -> NodeIdentityV0 {
    NodeIdentityV0 {
        chain_id: Digest32V0([1; 32]),
        validator_id: Digest32V0([2; 32]),
        application_id: Digest32V0([3; 32]),
        generation: 1,
    }
}

fn other_identity() -> NodeIdentityV0 {
    NodeIdentityV0 {
        generation: 2,
        ..identity()
    }
}

fn ingress() -> BoundIngressV0 {
    BoundIngressV0::derive(
        identity(),
        1,
        1,
        Digest32V0([4; 32]),
        Digest32V0([5; 32]),
        IngressFrameV0::new(Digest32V0([6; 32]), Digest32V0([7; 32]), 1, vec![8]).unwrap(),
    )
    .unwrap()
}

fn fixture() -> (Host, Rc<Controls>, Rc<Cell<NodeIdentityV0>>) {
    let controls = Rc::new(Controls::default());
    let identity_cell = Rc::new(Cell::new(identity()));
    let coordinator = FaultCoordinator {
        inner: ReferenceAuthorityCoordinatorV0::new(identity()),
        identity: Rc::clone(&identity_cell),
        controls: Rc::clone(&controls),
    };
    let host = PersistentValidatorHostV0::new(
        coordinator,
        ObservedIo(Rc::clone(&controls)),
        StepBudgetV0::default(),
    )
    .unwrap();
    (host, controls, identity_cell)
}

fn assert_fenced(host: &mut Host, controls: &Controls) {
    let polls = controls.polls.get();
    let applies = controls.applies.get();
    assert_ne!(host.readiness(), HostReadinessV0::Ready);
    assert!(matches!(host.step(), Err(HostErrorV0::NotReady)));
    assert!(matches!(
        host.prepare_bound_ingress(&ingress()),
        Err(HostErrorV0::NotReady)
    ));
    assert_eq!(controls.polls.get(), polls);
    assert_eq!(controls.applies.get(), applies);
}

#[test]
fn repeated_recovery_error_revokes_previous_readiness() {
    let (mut host, controls, _) = fixture();
    assert_eq!(host.recover().unwrap(), HostReadinessV0::Ready);
    controls.recovery.set(Fault::Error);
    assert!(host.recover().is_err());
    assert_fenced(&mut host, &controls);
    assert_eq!(host.recover().unwrap(), HostReadinessV0::Ready);
    assert_eq!(host.step().unwrap(), HostStepV0::Idle);
}

#[test]
fn invalid_resume_binding_revokes_previous_readiness() {
    let (mut host, controls, _) = fixture();
    host.recover().unwrap();
    controls.recovery.set(Fault::Binding);
    assert!(matches!(host.recover(), Err(HostErrorV0::Boundary(_))));
    assert_fenced(&mut host, &controls);
}

#[test]
fn recovery_panic_leaves_host_fenced() {
    let (mut host, controls, _) = fixture();
    host.recover().unwrap();
    controls.recovery.set(Fault::Panic);
    assert!(std::panic::catch_unwind(AssertUnwindSafe(|| host.recover())).is_err());
    assert_fenced(&mut host, &controls);
}

#[test]
fn apply_error_requires_recovery_even_before_a_write() {
    let (mut host, controls, _) = fixture();
    host.recover().unwrap();
    controls.apply.set(Fault::Error);
    assert!(host.prepare_bound_ingress(&ingress()).is_err());
    assert_fenced(&mut host, &controls);
    host.recover().unwrap();
    assert_eq!(
        host.prepare_bound_ingress(&ingress()).unwrap().durable_sequence,
        0
    );
}

#[test]
fn lost_acknowledgement_recovers_and_replays_the_same_record() {
    let (mut host, controls, _) = fixture();
    host.recover().unwrap();
    controls.apply.set(Fault::AfterWrite);
    assert!(host.prepare_bound_ingress(&ingress()).is_err());
    let retained = host.coordinator.inner.current().unwrap();
    assert_eq!(retained.durable_sequence, 0);
    assert_fenced(&mut host, &controls);
    host.recover().unwrap();
    assert_eq!(host.prepare_bound_ingress(&ingress()).unwrap(), retained);
    assert_eq!(host.prepare_bound_ingress(&ingress()).unwrap(), retained);
}

#[test]
fn apply_panic_leaves_host_fenced() {
    let (mut host, controls, _) = fixture();
    host.recover().unwrap();
    controls.apply.set(Fault::Panic);
    assert!(std::panic::catch_unwind(AssertUnwindSafe(|| {
        host.prepare_bound_ingress(&ingress())
    })).is_err());
    assert_fenced(&mut host, &controls);
}

#[test]
fn every_substituted_receipt_field_requires_fresh_recovery() {
    for fault in [Fault::Binding, Fault::Stage, Fault::Facts, Fault::Record] {
        let (mut host, controls, _) = fixture();
        host.recover().unwrap();
        controls.apply.set(fault);
        assert!(host.prepare_bound_ingress(&ingress()).is_err());
        assert_fenced(&mut host, &controls);
        host.recover().unwrap();
        let exact = host.prepare_bound_ingress(&ingress()).unwrap();
        assert_eq!(exact, host.coordinator.inner.current().unwrap());
    }
}

#[test]
fn malformed_peer_input_does_not_revoke_durable_readiness() {
    let (mut host, controls, _) = fixture();
    host.recover().unwrap();
    let mut malformed = ingress();
    malformed.frame.payload.push(9);
    assert!(host.prepare_bound_ingress(&malformed).is_err());
    assert_eq!(controls.applies.get(), 0);
    assert_eq!(host.readiness(), HostReadinessV0::Ready);
    host.prepare_bound_ingress(&ingress()).unwrap();
}

#[test]
fn ordinary_io_error_does_not_revoke_durable_readiness() {
    let (mut host, controls, _) = fixture();
    host.recover().unwrap();
    controls.io_error.set(true);
    assert!(matches!(host.step(), Err(HostErrorV0::Io(_))));
    assert_eq!(host.readiness(), HostReadinessV0::Ready);
    assert_eq!(host.step().unwrap(), HostStepV0::Idle);
}

#[test]
fn changed_identity_is_rejected_before_polling_or_applying() {
    let (mut host, controls, identity_cell) = fixture();
    host.recover().unwrap();
    identity_cell.set(other_identity());
    assert!(matches!(
        host.step(),
        Err(HostErrorV0::Boundary(BoundaryErrorV0::InvalidIdentity))
    ));
    assert_eq!(controls.polls.get(), 0);
    assert_fenced(&mut host, &controls);
    assert!(host.recover().is_err());
}

#[test]
fn identity_changed_during_recovery_cannot_become_ready() {
    let (mut host, controls, _) = fixture();
    controls.recovery.set(Fault::Identity);
    assert!(host.recover().is_err());
    assert_fenced(&mut host, &controls);
}

#[test]
fn identity_changed_during_apply_cannot_release_a_receipt() {
    let (mut host, controls, _) = fixture();
    host.recover().unwrap();
    controls.apply.set(Fault::Identity);
    assert!(host.prepare_bound_ingress(&ingress()).is_err());
    assert_fenced(&mut host, &controls);
}

#[test]
fn invalid_identity_is_rejected_at_construction() {
    let (host, controls, identity_cell) = fixture();
    let (coordinator, io) = host.into_parts();
    identity_cell.set(NodeIdentityV0 {
        generation: 0,
        ..identity()
    });
    assert!(matches!(
        PersistentValidatorHostV0::new(coordinator, io, StepBudgetV0::default()),
        Err(BoundaryErrorV0::InvalidIdentity)
    ));
    assert_eq!(controls.applies.get(), 0);
    assert_eq!(controls.polls.get(), 0);
}
