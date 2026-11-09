//! Error returns cannot bypass original owner-budget observation.
#![cfg(all(target_os = "linux", feature = "pq-root-v3"))]

#[path = "support/root_recovery_v3_fixture.rs"]
mod fixture;
use fixture::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use trnm_crypto_primitives::pq_root_v3::{RootSignatureV3, VerificationBudgetV3};
use trnm_pon_node::root_recovery_v3::*;

enum Refusal {
    Original,
    ReplaceBudget,
    SetCancellation(Arc<AtomicBool>),
}

impl Refusal {
    fn before_error(&self, budget: &mut OwnerBudgetV3) {
        match self {
            Self::Original => {}
            Self::ReplaceBudget => *budget = owner_budget(),
            Self::SetCancellation(signal) => signal.store(true, Ordering::Release),
        }
    }
}

struct RefusingWriter(Refusal);
impl RootWriterSignerV3 for RefusingWriter {
    fn sign(
        &mut self,
        _message: &[u8],
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Vec<RootSignatureV3>> {
        self.0.before_error(budget);
        Err(rejected("fixture writer refused"))
    }
}

struct RefusingTransport(Refusal);
impl RootAnchorTransportV3 for RefusingTransport {
    fn exchange(
        &mut self,
        _request: AnchorEnvelopeV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedAnchorReceiptV3> {
        self.0.before_error(budget);
        Err(rejected("fixture transport refused"))
    }
}

fn budget_with_signal(signal: Arc<AtomicBool>) -> OwnerBudgetV3 {
    let deadline = Instant::now() + Duration::from_secs(120);
    OwnerBudgetV3::new(
        VerificationBudgetV3::with_deadline(4096, deadline).unwrap(),
        deadline,
        signal,
    )
    .unwrap()
}

fn writer_refusal(h: &Harness, refusal: Refusal, budget: &mut OwnerBudgetV3) -> String {
    RootOwnerV3::create(
        &h.path(),
        h.enrollment.clone(),
        RefusingWriter(refusal),
        h.service.clone(),
        budget,
    )
    .err()
    .unwrap()
    .to_string()
}

fn transport_refusal(h: &Harness, refusal: Refusal, budget: &mut OwnerBudgetV3) -> String {
    RootOwnerV3::create(
        &h.path(),
        h.enrollment.clone(),
        Writer { malformed: false },
        RefusingTransport(refusal),
        budget,
    )
    .err()
    .unwrap()
    .to_string()
}

#[test]
fn native_budget_v4_writer_error_cannot_hide_budget_replacement() {
    let h = Harness::new();
    let error = writer_refusal(&h, Refusal::ReplaceBudget, &mut owner_budget());
    assert_eq!(error, "ROOT_OWNER_CALLBACK_REPLACED_BUDGET");
    assert_eq!(h.service.state.borrow().calls, 0);
}

#[test]
fn native_budget_v4_transport_error_cannot_hide_budget_replacement() {
    let h = Harness::new();
    let error = transport_refusal(&h, Refusal::ReplaceBudget, &mut owner_budget());
    assert_eq!(error, "ROOT_OWNER_CALLBACK_REPLACED_BUDGET");
}

#[test]
fn native_budget_v4_writer_error_latches_observed_external_cancellation() {
    let h = Harness::new();
    let signal = Arc::new(AtomicBool::new(false));
    let mut budget = budget_with_signal(signal.clone());
    let error = writer_refusal(&h, Refusal::SetCancellation(signal.clone()), &mut budget);
    assert_eq!(error, "ROOT_OWNER_ORIGINAL_BUDGET_EXPIRED_OR_CANCELLED");
    signal.store(false, Ordering::Release);
    assert_eq!(budget.check().unwrap_err().to_string(), error);
    assert_eq!(h.service.state.borrow().calls, 0);
}

#[test]
fn native_budget_v4_transport_error_latches_observed_external_cancellation() {
    let h = Harness::new();
    let signal = Arc::new(AtomicBool::new(false));
    let mut budget = budget_with_signal(signal.clone());
    let error = transport_refusal(&h, Refusal::SetCancellation(signal.clone()), &mut budget);
    assert_eq!(error, "ROOT_OWNER_ORIGINAL_BUDGET_EXPIRED_OR_CANCELLED");
    signal.store(false, Ordering::Release);
    assert_eq!(budget.check().unwrap_err().to_string(), error);
}

#[test]
fn native_budget_v4_unmodified_writer_error_is_preserved() {
    let h = Harness::new();
    let mut budget = owner_budget();
    assert_eq!(
        writer_refusal(&h, Refusal::Original, &mut budget),
        "fixture writer refused"
    );
    assert!(budget.check().is_ok());
    assert_eq!(h.service.state.borrow().calls, 0);
}

#[test]
fn native_budget_v4_unmodified_transport_error_is_preserved() {
    let h = Harness::new();
    let mut budget = owner_budget();
    assert_eq!(
        transport_refusal(&h, Refusal::Original, &mut budget),
        "fixture transport refused"
    );
    assert!(budget.check().is_ok());
}
