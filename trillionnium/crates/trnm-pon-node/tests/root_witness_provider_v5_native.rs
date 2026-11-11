//! Real Root SQLite/provider files and PQ signatures through the V5 read route.
//! The witness is a separate in-process fixture, not physical custody evidence.
#![cfg(all(target_os = "linux", feature = "pq-root-v3"))]

#[path = "support/root_recovery_v3_fixture.rs"]
mod fixture;
use fixture::*;
use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::OnceLock;
use trnm_pon_node::root_recovery_v3::effect_readback_v4::*;
use trnm_pon_node::root_recovery_v3::witnessed_v5::*;
use trnm_pon_node::root_recovery_v3::*;
use trnm_release_bundle::root_recovery_v3::{DigestV3, ReleaseUseV3};

fn witness_keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(Keys::generate)
}
fn provider_keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(Keys::generate)
}
fn material(attempt: u8) -> ReadbackMaterialV4<'static> {
    ReadbackMaterialV4 {
        kind: ReleaseUseV3::Install,
        attempt: [attempt; 32],
        bundle: b"complete bundle",
        contract: b"complete launch contract",
        artifact: b"held actual executable",
    }
}

struct WitnessState {
    head: JournalHeadV3,
    available: bool,
    reads: usize,
    advances: usize,
}
#[derive(Clone)]
struct Witness {
    policy: WitnessPolicyV5,
    state: Rc<RefCell<WitnessState>>,
}
impl RootWitnessTransportV5 for Witness {
    fn exchange(
        &mut self,
        envelope: WitnessEnvelopeV5,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedWitnessReceiptV5> {
        envelope.verify_writer(&self.policy, budget)?;
        let mut state = self.state.borrow_mut();
        if !state.available {
            return Err(rejected("fixture live witness unavailable"));
        }
        let outcome = match (envelope.request.expected, envelope.request.target) {
            (None, None) => {
                state.reads += 1;
                WitnessOutcomeV5::Current
            }
            (Some(previous), Some(target)) if previous == state.head => {
                state.advances += 1;
                state.head = target;
                WitnessOutcomeV5::Advanced
            }
            _ => WitnessOutcomeV5::Mismatch,
        };
        let receipt = WitnessReceiptV5::for_request(&envelope.request, state.head, outcome)?;
        let approvals = witness_keys().quorum(&receipt.message()?);
        Ok(SignedWitnessReceiptV5 { receipt, approvals })
    }
}

struct Ready {
    harness: Harness,
    witness: Witness,
    root: Option<WitnessedRootOwnerV5>,
    enrollment: ProviderEnrollmentV4,
    path: PathBuf,
    operation: DigestV3,
    head: JournalHeadV3,
}
impl Ready {
    fn new(attempt: u8) -> Self {
        let harness = Harness::new();
        let witness = Witness {
            policy: WitnessPolicyV5::new(
                &harness.enrollment,
                [91; 64],
                1,
                witness_keys().roster.clone(),
            )
            .unwrap(),
            state: Rc::new(RefCell::new(WitnessState {
                head: harness.enrollment.initial_head().unwrap(),
                available: true,
                reads: 0,
                advances: 0,
            })),
        };
        let mut root = WitnessedRootOwnerV5::create(
            &harness.path(),
            harness.enrollment.clone(),
            Writer { malformed: false },
            harness.service.clone(),
            Self::client(&witness),
            &mut owner_budget(),
        )
        .unwrap();
        let committed = root
            .apply(&normal(&state(), attempt), 110, &mut owner_budget())
            .unwrap();
        let enrollment = root
            .provider_readback_enrollment_v4(
                committed.operation_id,
                [77; 32],
                provider_keys().roster.clone(),
                material(attempt),
                &mut owner_budget(),
            )
            .unwrap();
        let path = harness.directory.path().join("provider.evidence");
        Self {
            harness,
            witness,
            root: Some(root),
            enrollment,
            path,
            operation: committed.operation_id,
            head: committed.head,
        }
    }
    fn client(witness: &Witness) -> RootWitnessV5 {
        RootWitnessV5::new(
            witness.policy.clone(),
            Writer { malformed: false },
            witness.clone(),
        )
    }
    fn journal(&self) -> ProviderEvidenceJournalV4 {
        ProviderEvidenceJournalV4::create(&self.path, self.enrollment.clone(), &mut owner_budget())
            .unwrap()
    }
    fn reopen_journal(&self) -> ProviderEvidenceJournalV4 {
        ProviderEvidenceJournalV4::open_existing(
            &self.path,
            self.enrollment.clone(),
            &mut owner_budget(),
        )
        .unwrap()
    }
    fn reopen_root(&mut self) {
        drop(self.root.take());
        self.root = Some(
            WitnessedRootOwnerV5::open_existing(
                &self.harness.path(),
                self.harness.enrollment.clone(),
                Writer { malformed: false },
                self.harness.service.clone(),
                Self::client(&self.witness),
                &mut owner_budget(),
            )
            .unwrap(),
        );
    }
    fn assert_no_new_root_operation(&self) {
        assert_eq!(self.witness.state.borrow().head, self.head);
        assert_eq!(self.witness.state.borrow().advances, 1);
        assert_eq!(self.harness.service.state.borrow().cas_calls, 1);
        assert_eq!(self.harness.pending(), 0);
    }
}

#[derive(Clone, Copy)]
enum ProviderFault {
    None,
    LostReply,
    RegressWitness,
    ReplaceBudget,
    ReplaceBudgetAndError,
    Cancel,
}
struct Provider {
    path: PathBuf,
    witness: Witness,
    initial: JournalHeadV3,
    fault: ProviderFault,
    outcome: ProviderOutcomeV4,
    requests: Vec<ProviderRequestV4>,
}
impl Provider {
    fn new(ready: &Ready) -> Self {
        Self {
            path: ready.path.clone(),
            witness: ready.witness.clone(),
            initial: ready.harness.enrollment.initial_head().unwrap(),
            fault: ProviderFault::None,
            outcome: ProviderOutcomeV4::Applied,
            requests: Vec::new(),
        }
    }
}
impl RootProviderReadbackTransportV4 for Provider {
    fn readback(
        &mut self,
        request: &ProviderRequestV4,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedProviderReceiptV4> {
        budget.check()?;
        self.requests.push(request.clone());
        let stored = fs::read(&self.path)?;
        let message = request.message()?;
        assert!(stored.windows(message.len()).any(|part| part == message));
        if matches!(self.fault, ProviderFault::LostReply) {
            return Err(rejected("fixture provider read reply lost"));
        }
        let mut id = [89; 32];
        id[..8].copy_from_slice(&(self.requests.len() as u64).to_be_bytes());
        let receipt = ProviderReceiptV4::for_request(
            request,
            id,
            self.outcome,
            ProviderReconciliationV4::None,
        )?;
        let approvals = provider_keys().quorum(&receipt.message()?);
        match self.fault {
            ProviderFault::RegressWitness => self.witness.state.borrow_mut().head = self.initial,
            ProviderFault::ReplaceBudget | ProviderFault::ReplaceBudgetAndError => {
                *budget = owner_budget();
            }
            ProviderFault::Cancel => budget.cancel(),
            _ => {}
        }
        if matches!(self.fault, ProviderFault::ReplaceBudgetAndError) {
            return Err(rejected("fixture provider replaced budget then failed"));
        }
        Ok(SignedProviderReceiptV4 { receipt, approvals })
    }
}
fn read(
    ready: &mut Ready,
    journal: &mut ProviderEvidenceJournalV4,
    provider: &mut Provider,
) -> RootOwnerResultV3<ProviderEvidenceV4> {
    journal.reconcile_witnessed_v5(ready.root.as_mut().unwrap(), provider, &mut owner_budget())
}
fn no_effect_authority(evidence: &ProviderEvidenceV4) {
    assert!(!evidence.authorization_granted());
    assert!(!evidence.redispatch_permitted());
    assert!(!evidence.actual_external_effects_verified());
}

#[test]
fn native_witness_provider_v5_created_and_cold_owners_read_the_same_operation() {
    let mut ready = Ready::new(41);
    let mut journal = ready.journal();
    let mut provider = Provider::new(&ready);
    let before = ready.witness.state.borrow().reads;
    let observed = read(&mut ready, &mut journal, &mut provider).unwrap();
    assert_eq!(observed.operation_id, ready.operation);
    assert_eq!(observed.last_known, Some(ProviderOutcomeV4::Applied));
    assert!(ready.witness.state.borrow().reads >= before + 4);
    no_effect_authority(&observed);
    drop(journal);
    ready.reopen_root();
    let mut journal = ready.reopen_journal();
    assert_eq!(journal.evidence(&mut owner_budget()).unwrap(), observed);
    let next = read(&mut ready, &mut journal, &mut provider).unwrap();
    assert_eq!(next.readbacks_started, 2);
    assert_eq!(
        provider.requests[0].operation_id,
        provider.requests[1].operation_id
    );
    assert_ne!(
        provider.requests[0].challenge,
        provider.requests[1].challenge
    );
    ready.assert_no_new_root_operation();
}

#[test]
fn native_witness_provider_v5_lost_read_reply_reopens_pending_without_redispatch() {
    let mut ready = Ready::new(42);
    let mut journal = ready.journal();
    let mut provider = Provider::new(&ready);
    provider.fault = ProviderFault::LostReply;
    assert!(read(&mut ready, &mut journal, &mut provider).is_err());
    assert!(journal.evidence(&mut owner_budget()).is_err());
    drop(journal);
    ready.reopen_root();
    let mut journal = ready.reopen_journal();
    let pending = journal.evidence(&mut owner_budget()).unwrap();
    assert!(pending.pending);
    assert_eq!(pending.readbacks_started, 1);
    assert_eq!(pending.operation_id, ready.operation);
    no_effect_authority(&pending);
    provider.fault = ProviderFault::None;
    let result = read(&mut ready, &mut journal, &mut provider).unwrap();
    assert!(!result.pending);
    assert_eq!(result.readbacks_started, 2);
    assert_eq!(
        provider.requests[0].operation_id,
        provider.requests[1].operation_id
    );
    assert_eq!(
        provider.requests[0].intent_commitment,
        provider.requests[1].intent_commitment
    );
    assert_eq!(
        provider.requests[0].enrollment_commitment,
        provider.requests[1].enrollment_commitment
    );
    assert_ne!(
        provider.requests[0].challenge,
        provider.requests[1].challenge
    );
    ready.assert_no_new_root_operation();
}

#[test]
fn native_witness_provider_v5_unknown_does_not_erase_applied_or_grant_retry() {
    let mut ready = Ready::new(43);
    let mut journal = ready.journal();
    let mut provider = Provider::new(&ready);
    read(&mut ready, &mut journal, &mut provider).unwrap();
    provider.outcome = ProviderOutcomeV4::Unknown;
    let unknown = read(&mut ready, &mut journal, &mut provider).unwrap();
    assert_eq!(unknown.last_known, Some(ProviderOutcomeV4::Applied));
    no_effect_authority(&unknown);
    drop(journal);
    ready.reopen_root();
    assert_eq!(
        ready
            .reopen_journal()
            .evidence(&mut owner_budget())
            .unwrap(),
        unknown
    );
    ready.assert_no_new_root_operation();
}

#[test]
fn native_witness_provider_v5_unavailable_or_regressed_witness_prevents_read() {
    for unavailable in [true, false] {
        let mut ready = Ready::new(44);
        let mut journal = ready.journal();
        let mut provider = Provider::new(&ready);
        let before = fs::read(&ready.path).unwrap();
        if unavailable {
            ready.witness.state.borrow_mut().available = false;
        } else {
            ready.witness.state.borrow_mut().head =
                ready.harness.enrollment.initial_head().unwrap();
        }
        assert!(read(&mut ready, &mut journal, &mut provider).is_err());
        assert!(provider.requests.is_empty());
        assert_eq!(fs::read(&ready.path).unwrap(), before);
        assert_eq!(ready.harness.service.state.borrow().cas_calls, 1);
    }
}

#[test]
fn native_witness_provider_v5_regression_during_read_retains_exact_pending_request() {
    let mut ready = Ready::new(45);
    let mut journal = ready.journal();
    let mut provider = Provider::new(&ready);
    provider.fault = ProviderFault::RegressWitness;
    let error = read(&mut ready, &mut journal, &mut provider).unwrap_err();
    assert_eq!(
        error.to_string(),
        "ROOT_WITNESS_V5_REGRESSION_OR_EQUIVOCATION"
    );
    assert_eq!(provider.requests.len(), 1);
    assert!(journal.evidence(&mut owner_budget()).is_err());
    drop(journal);
    let pending = ready
        .reopen_journal()
        .evidence(&mut owner_budget())
        .unwrap();
    assert!(pending.pending);
    assert_eq!(pending.operation_id, ready.operation);
    assert_eq!(pending.last_known, None);
    no_effect_authority(&pending);
    assert!(ready
        .root
        .as_mut()
        .unwrap()
        .context(&mut owner_budget())
        .is_err());
    assert_eq!(ready.harness.service.state.borrow().cas_calls, 1);
}

#[test]
fn native_witness_provider_v5_provider_roster_cannot_reuse_witness_keys() {
    let mut ready = Ready::new(46);
    let error = ready
        .root
        .as_mut()
        .unwrap()
        .provider_readback_enrollment_v4(
            ready.operation,
            [77; 32],
            witness_keys().roster.clone(),
            material(46),
            &mut owner_budget(),
        )
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "ROOT_PROVIDER_WITNESS_CROSS_ROLE_KEY");
    assert!(ready
        .root
        .as_mut()
        .unwrap()
        .context(&mut owner_budget())
        .is_err());
    ready.assert_no_new_root_operation();
}

#[test]
fn native_witness_provider_v5_callback_cannot_replace_budget_or_clear_cancellation() {
    for fault in [
        ProviderFault::ReplaceBudget,
        ProviderFault::ReplaceBudgetAndError,
        ProviderFault::Cancel,
    ] {
        let mut ready = Ready::new(47);
        let mut journal = ready.journal();
        let mut provider = Provider::new(&ready);
        provider.fault = fault;
        let error = read(&mut ready, &mut journal, &mut provider).unwrap_err();
        assert!(error.to_string().contains("BUDGET") || error.to_string().contains("CANCEL"));
        assert_eq!(provider.requests.len(), 1);
        assert!(journal.evidence(&mut owner_budget()).is_err());
        drop(journal);
        let pending = ready
            .reopen_journal()
            .evidence(&mut owner_budget())
            .unwrap();
        assert!(pending.pending);
        no_effect_authority(&pending);
        ready.assert_no_new_root_operation();
    }
}

#[test]
fn native_witness_provider_v5_historical_material_and_operation_are_exact() {
    for field in 0..3 {
        let mut ready = Ready::new(48);
        let mut actual = material(48);
        let mut operation = ready.operation;
        match field {
            0 => operation[0] ^= 1,
            1 => actual.attempt = [49; 32],
            2 => actual.artifact = b"different executable",
            _ => unreachable!(),
        }
        assert!(ready
            .root
            .as_mut()
            .unwrap()
            .provider_readback_enrollment_v4(
                operation,
                [77; 32],
                provider_keys().roster.clone(),
                actual,
                &mut owner_budget(),
            )
            .is_err());
        ready.assert_no_new_root_operation();
    }
}
