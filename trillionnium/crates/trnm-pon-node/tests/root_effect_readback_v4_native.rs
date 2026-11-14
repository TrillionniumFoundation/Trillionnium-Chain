//! Native readback declarations and file durability; no production effects.
#![cfg(all(target_os = "linux", feature = "pq-root-v3"))]
#[path = "support/root_recovery_v3_fixture.rs"]
mod fixture;
use fixture::*;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::OnceLock;
use trnm_crypto_primitives::pq_root_v3::VerificationBudgetV3;
use trnm_pon_node::root_recovery_v3::effect_readback_v4::*;
use trnm_pon_node::root_recovery_v3::*;
use trnm_release_bundle::root_recovery_v3::{DigestV3, ReleaseUseV3, RootActionV3};

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
struct Ready {
    h: Harness,
    root: RootOwnerV3,
    enrollment: ProviderEnrollmentV4,
    path: std::path::PathBuf,
    operation: DigestV3,
    attempt: u8,
}
impl Ready {
    fn new(attempt: u8) -> Self {
        let h = Harness::new();
        let mut original = h.create();
        let committed = original
            .apply(&normal(&state(), attempt), 110, &mut owner_budget())
            .unwrap();
        drop(original);
        let floor = RecoveryFloorV4::from_external_pin(&h.enrollment, committed.head).unwrap();
        let mut root = RootOwnerV3::open_existing_with_recovery_floor(
            &h.path(),
            h.enrollment.clone(),
            Writer { malformed: false },
            h.service.clone(),
            floor,
            &mut owner_budget(),
        )
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
        let path = h.directory.path().join("provider-v4.evidence");
        Self {
            h,
            root,
            enrollment,
            path,
            operation: committed.operation_id,
            attempt,
        }
    }
    fn journal(&self) -> ProviderEvidenceJournalV4 {
        ProviderEvidenceJournalV4::create(&self.path, self.enrollment.clone(), &mut owner_budget())
            .unwrap()
    }
    fn reopen(&self) -> ProviderEvidenceJournalV4 {
        ProviderEvidenceJournalV4::open_existing(
            &self.path,
            self.enrollment.clone(),
            &mut owner_budget(),
        )
        .unwrap()
    }
}
#[derive(Clone, Copy)]
enum ProviderFault {
    None,
    LostReply,
    WrongChallenge,
    WrongOperation,
    WrongIntent,
    WrongProvider,
    WrongEnrollment,
    WrongRequest,
    WrongScope,
    WrongEpoch,
    CorruptMl,
    CorruptSl,
    MissingFamily,
    ReplaceBudget,
    ReplaceBudgetAndError,
    Cancel,
}
struct Transport {
    fault: ProviderFault,
    outcome: ProviderOutcomeV4,
    reconciliation: ProviderReconciliationV4,
    calls: usize,
    requests: Vec<ProviderRequestV4>,
    path: std::path::PathBuf,
}
impl Transport {
    fn new(path: &std::path::Path) -> Self {
        Self {
            fault: ProviderFault::None,
            outcome: ProviderOutcomeV4::Applied,
            reconciliation: ProviderReconciliationV4::None,
            calls: 0,
            requests: Vec::new(),
            path: path.to_path_buf(),
        }
    }
}
impl RootProviderReadbackTransportV4 for Transport {
    fn readback(
        &mut self,
        request: &ProviderRequestV4,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedProviderReceiptV4> {
        budget.check()?;
        self.calls += 1;
        self.requests.push(request.clone());
        let stored = fs::read(&self.path)?;
        let message = request.message()?;
        assert!(
            stored.windows(message.len()).any(|bytes| bytes == message),
            "exact request was written before transport"
        );
        if matches!(self.fault, ProviderFault::LostReply) {
            return Err(rejected("test lookup response unavailable"));
        }
        if matches!(self.fault, ProviderFault::ReplaceBudgetAndError) {
            *budget = owner_budget();
            return Err(rejected("test callback error after replacing budget"));
        }
        let mut id = [89; 32];
        id[..8].copy_from_slice(&(self.calls as u64).to_be_bytes());
        let mut receipt =
            ProviderReceiptV4::for_request(request, id, self.outcome, self.reconciliation)?;
        match self.fault {
            ProviderFault::WrongChallenge => receipt.challenge[0] ^= 1,
            ProviderFault::WrongOperation => receipt.operation_id[0] ^= 1,
            ProviderFault::WrongIntent => receipt.intent_commitment[0] ^= 1,
            ProviderFault::WrongProvider => receipt.provider[0] ^= 1,
            ProviderFault::WrongEnrollment => receipt.enrollment_commitment[0] ^= 1,
            ProviderFault::WrongRequest => receipt.request_digest[0] ^= 1,
            ProviderFault::WrongScope => receipt.scope[0] ^= 1,
            ProviderFault::WrongEpoch => {
                receipt.reconciled_epoch = Some(request.orphaned_at.unwrap() + 1)
            }
            _ => {}
        }
        let mut approvals = provider_keys().quorum(&receipt.message()?);
        match self.fault {
            ProviderFault::CorruptMl => approvals[0].signature[0] ^= 1,
            ProviderFault::CorruptSl => approvals[2].signature[0] ^= 1,
            ProviderFault::MissingFamily => approvals.truncate(2),
            ProviderFault::ReplaceBudget => *budget = owner_budget(),
            ProviderFault::Cancel => budget.cancel(),
            _ => {}
        }
        Ok(SignedProviderReceiptV4 { receipt, approvals })
    }
}

#[test]
fn native_provider_v4_real_declaration_reopens_without_effect_authority() {
    let mut ready = Ready::new(41);
    let mut journal = ready.journal();
    let mut transport = Transport::new(&ready.path);
    let observed = journal
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .unwrap();
    assert_eq!(observed.operation_id, ready.operation);
    assert_eq!(observed.readbacks_started, 1);
    assert_eq!(observed.last_known, Some(ProviderOutcomeV4::Applied));
    assert!(!observed.pending);
    assert!(!observed.authorization_granted());
    assert!(!observed.redispatch_permitted());
    assert!(!observed.actual_external_effects_verified());
    drop(journal);
    assert_eq!(
        ready.reopen().evidence(&mut owner_budget()).unwrap(),
        observed
    );
    let mut bytes = fs::read(&ready.path).unwrap();
    let signature_byte = bytes.len() - 65;
    bytes[signature_byte] ^= 1;
    fs::write(&ready.path, bytes).unwrap();
    assert!(
        ProviderEvidenceJournalV4::open_existing(
            &ready.path,
            ready.enrollment.clone(),
            &mut owner_budget()
        )
        .is_err(),
        "reopening verifies the retained native signature again"
    );
}

#[test]
fn native_provider_v4_enrollment_requires_floor_complete_bytes_kind_and_attempt() {
    let ready = Ready::new(42);
    let op = ready.operation;
    let h = &ready.h;
    let floor = ready.root.recovery_floor().unwrap().clone();
    drop(ready.root);
    let mut unpinned = h.open().unwrap();
    assert!(unpinned
        .provider_readback_enrollment_v4(
            op,
            [77; 32],
            provider_keys().roster.clone(),
            material(42),
            &mut owner_budget()
        )
        .is_err());
    drop(unpinned);
    for field in 0..5 {
        let mut owner = RootOwnerV3::open_existing_with_recovery_floor(
            &h.path(),
            h.enrollment.clone(),
            Writer { malformed: false },
            h.service.clone(),
            floor.clone(),
            &mut owner_budget(),
        )
        .unwrap();
        let mut actual = material(42);
        match field {
            0 => actual.kind = ReleaseUseV3::FinalUse,
            1 => actual.attempt = [43; 32],
            2 => actual.bundle = b"changed bundle",
            3 => actual.contract = b"changed contract",
            4 => actual.artifact = b"changed artifact",
            _ => unreachable!(),
        }
        assert!(owner
            .provider_readback_enrollment_v4(
                op,
                [77; 32],
                provider_keys().roster.clone(),
                actual,
                &mut owner_budget()
            )
            .is_err());
    }
}

#[test]
fn native_provider_v4_lost_and_unknown_reads_keep_original_operation_pending() {
    let mut ready = Ready::new(43);
    let mut journal = ready.journal();
    let mut transport = Transport::new(&ready.path);
    transport.fault = ProviderFault::LostReply;
    assert!(journal
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .is_err());
    drop(journal);
    let mut reopened = ready.reopen();
    let pending = reopened.evidence(&mut owner_budget()).unwrap();
    assert!(pending.pending);
    assert_eq!(pending.last_known, None);
    transport.fault = ProviderFault::None;
    transport.outcome = ProviderOutcomeV4::Unknown;
    let unknown = reopened
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .unwrap();
    assert_eq!(unknown.last_known, None);
    assert!(!unknown.pending);
    transport.outcome = ProviderOutcomeV4::NotApplied;
    let known = reopened
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .unwrap();
    assert_eq!(known.last_known, Some(ProviderOutcomeV4::NotApplied));
    assert!(!known.redispatch_permitted());
    assert_eq!(known.readbacks_started, 3);
    assert!(transport
        .requests
        .iter()
        .all(|request| request.operation_id == ready.operation));
    assert!(transport
        .requests
        .windows(2)
        .all(|pair| pair[0].challenge != pair[1].challenge));
}

#[test]
fn native_provider_v4_complete_request_and_both_signature_families_are_required() {
    for fault in [
        ProviderFault::WrongChallenge,
        ProviderFault::WrongOperation,
        ProviderFault::WrongIntent,
        ProviderFault::WrongProvider,
        ProviderFault::WrongEnrollment,
        ProviderFault::WrongRequest,
        ProviderFault::WrongScope,
        ProviderFault::CorruptMl,
        ProviderFault::CorruptSl,
        ProviderFault::MissingFamily,
    ] {
        let mut ready = Ready::new(44);
        let mut journal = ready.journal();
        let mut transport = Transport::new(&ready.path);
        transport.fault = fault;
        assert!(journal
            .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
            .is_err());
        drop(journal);
        let pending = ready.reopen().evidence(&mut owner_budget()).unwrap();
        assert!(pending.pending);
        assert_eq!(pending.last_known, None);
    }
}

#[test]
fn native_provider_v4_callback_cannot_replace_cancel_or_replenish_budget() {
    for fault in [
        ProviderFault::ReplaceBudget,
        ProviderFault::ReplaceBudgetAndError,
        ProviderFault::Cancel,
    ] {
        let mut ready = Ready::new(45);
        let mut journal = ready.journal();
        let mut transport = Transport::new(&ready.path);
        transport.fault = fault;
        let mut budget = owner_budget();
        let error = journal
            .reconcile(&mut ready.root, &mut transport, &mut budget)
            .err()
            .unwrap();
        if matches!(fault, ProviderFault::ReplaceBudgetAndError) {
            assert!(error.to_string().contains("CALLBACK_REPLACED_BUDGET"));
        }
        assert!(
            journal.evidence(&mut owner_budget()).is_err(),
            "session remains fenced even with a new quota"
        );
        drop(journal);
        assert!(
            ready
                .reopen()
                .evidence(&mut owner_budget())
                .unwrap()
                .pending
        );
    }
}

#[test]
fn native_provider_v4_orphan_epochs_require_explicit_same_epoch_reconciliation() {
    let mut ready = Ready::new(46);
    let mut journal = ready.journal();
    let mut transport = Transport::new(&ready.path);
    journal
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .unwrap();
    journal
        .observe_orphan_epoch(10, &mut owner_budget())
        .unwrap();
    let ordinary = journal
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .unwrap();
    assert_eq!(ordinary.reconciliation, ReconciliationStateV4::Required);
    transport.reconciliation = ProviderReconciliationV4::LiabilityRetained;
    let explicit = journal
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .unwrap();
    assert_eq!(
        explicit.reconciliation,
        ReconciliationStateV4::LiabilityRetained
    );
    journal
        .observe_orphan_epoch(11, &mut owner_budget())
        .unwrap();
    transport.fault = ProviderFault::WrongEpoch;
    assert!(journal
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .is_err());
    drop(journal);
    let mut reopened = ready.reopen();
    let retained = reopened.evidence(&mut owner_budget()).unwrap();
    assert_eq!(retained.orphaned_at, Some(11));
    assert_eq!(retained.reconciliation, ReconciliationStateV4::Required);
    transport.fault = ProviderFault::None;
    transport.outcome = ProviderOutcomeV4::Compensated;
    transport.reconciliation = ProviderReconciliationV4::Compensated;
    let compensation = reopened
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .unwrap();
    assert_eq!(
        compensation.reconciliation,
        ReconciliationStateV4::Compensated
    );
    assert!(!compensation.actual_external_effects_verified());
    assert_eq!(
        compensation.orphan_history.get(&10),
        Some(&ReconciliationStateV4::LiabilityRetained)
    );
    assert_eq!(
        compensation.orphan_history.get(&11),
        Some(&ReconciliationStateV4::Compensated)
    );
}

#[test]
fn native_provider_v4_unknown_does_not_erase_known_outcome_and_conflicts_refuse() {
    let mut ready = Ready::new(47);
    let mut journal = ready.journal();
    let mut transport = Transport::new(&ready.path);
    journal
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .unwrap();
    transport.outcome = ProviderOutcomeV4::Unknown;
    assert_eq!(
        journal
            .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
            .unwrap()
            .last_known,
        Some(ProviderOutcomeV4::Applied)
    );
    transport.outcome = ProviderOutcomeV4::NotApplied;
    assert!(journal
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .is_err());
    drop(journal);
    let retained = ready.reopen().evidence(&mut owner_budget()).unwrap();
    assert_eq!(retained.last_known, Some(ProviderOutcomeV4::Applied));
    assert!(retained.pending);
}

#[test]
fn native_provider_v4_replays_original_operation_after_authority_rotation() {
    let mut ready = Ready::new(48);
    let mut journal = ready.journal();
    let mut model = state();
    model
        .apply(
            &normal(&state(), ready.attempt),
            110,
            &mut VerificationBudgetV3::new(64).unwrap(),
        )
        .unwrap();
    let rotation = fixtures().root.envelope(
        statement(
            &model,
            49,
            RootActionV3::Rotate {
                next: fixtures().next.policy(),
            },
        ),
        Some(&fixtures().next),
    );
    ready
        .root
        .apply(&rotation, 120, &mut owner_budget())
        .unwrap();
    let mut transport = Transport::new(&ready.path);
    let evidence = journal
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .unwrap();
    assert_eq!(evidence.operation_id, ready.operation);
    assert!(!evidence.authorization_granted());
    assert!(ready
        .root
        .observe_current_intent(ready.operation, 121, &mut owner_budget())
        .is_err());
}

#[test]
fn native_provider_v4_later_root_provider_alias_refuses_before_transport() {
    let mut ready = Ready::new(50);
    let mut journal = ready.journal();
    let mut model = state();
    model
        .apply(
            &normal(&state(), ready.attempt),
            110,
            &mut VerificationBudgetV3::new(64).unwrap(),
        )
        .unwrap();
    let rotation = fixtures().root.envelope(
        statement(
            &model,
            51,
            RootActionV3::Rotate {
                next: provider_keys().policy(),
            },
        ),
        Some(provider_keys()),
    );
    ready
        .root
        .apply(&rotation, 120, &mut owner_budget())
        .unwrap();
    let mut transport = Transport::new(&ready.path);
    let error = journal
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .err()
        .unwrap();
    assert!(error.to_string().contains("CROSS_ROLE_KEY"));
    assert_eq!(transport.calls, 0);
    drop(journal);
    assert_eq!(
        ready
            .reopen()
            .evidence(&mut owner_budget())
            .unwrap()
            .readbacks_started,
        0
    );
}

#[test]
fn native_provider_v4_foreign_replaced_linked_and_truncated_journals_refuse() {
    let ready = Ready::new(52);
    let foreign = ready.h.directory.path().join("foreign");
    fs::write(&foreign, b"foreign protocol state").unwrap();
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).unwrap();
    let original = fs::read(&foreign).unwrap();
    assert!(ProviderEvidenceJournalV4::open_existing(
        &foreign,
        ready.enrollment.clone(),
        &mut owner_budget()
    )
    .is_err());
    assert_eq!(fs::read(&foreign).unwrap(), original);
    let mut journal = ready.journal();
    assert!(ProviderEvidenceJournalV4::create(
        &ready.path,
        ready.enrollment.clone(),
        &mut owner_budget()
    )
    .is_err());
    assert!(ProviderEvidenceJournalV4::open_existing(
        &ready.path,
        ready.enrollment.clone(),
        &mut owner_budget()
    )
    .is_err());
    let linked = ready.h.directory.path().join("linked");
    symlink(&ready.path, &linked).unwrap();
    assert!(ProviderEvidenceJournalV4::open_existing(
        &linked,
        ready.enrollment.clone(),
        &mut owner_budget()
    )
    .is_err());
    let replacement = ready.h.directory.path().join("replacement");
    fs::copy(&ready.path, &replacement).unwrap();
    fs::rename(&replacement, &ready.path).unwrap();
    assert!(journal.evidence(&mut owner_budget()).is_err());
    drop(journal);
    let mut journal = ready.reopen();
    journal
        .observe_orphan_epoch(1, &mut owner_budget())
        .unwrap();
    drop(journal);
    let mut bytes = fs::read(&ready.path).unwrap();
    bytes.pop();
    fs::write(&ready.path, bytes).unwrap();
    assert!(ProviderEvidenceJournalV4::open_existing(
        &ready.path,
        ready.enrollment.clone(),
        &mut owner_budget()
    )
    .is_err());
}

#[test]
fn native_provider_v4_unresolved_orphan_is_not_replaced_by_new_epoch() {
    let mut ready = Ready::new(53);
    let mut journal = ready.journal();
    journal
        .observe_orphan_epoch(10, &mut owner_budget())
        .unwrap();
    let before = fs::read(&ready.path).unwrap();
    assert!(journal
        .observe_orphan_epoch(11, &mut owner_budget())
        .is_err());
    assert_eq!(fs::read(&ready.path).unwrap(), before);
    drop(journal);
    let mut reopened = ready.reopen();
    let evidence = reopened.evidence(&mut owner_budget()).unwrap();
    assert_eq!(evidence.orphaned_at, Some(10));
    assert_eq!(evidence.reconciliation, ReconciliationStateV4::Required);
    let mut transport = Transport::new(&ready.path);
    transport.reconciliation = ProviderReconciliationV4::LiabilityRetained;
    reopened
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .unwrap();
    assert_eq!(
        reopened
            .observe_orphan_epoch(11, &mut owner_budget())
            .unwrap()
            .orphaned_at,
        Some(11)
    );
}

#[test]
fn native_provider_v4_oversized_journal_refuses_before_lookup() {
    let mut ready = Ready::new(54);
    let mut journal = ready.journal();
    fs::OpenOptions::new()
        .write(true)
        .open(&ready.path)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    let mut transport = Transport::new(&ready.path);
    assert!(journal
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .is_err());
    assert_eq!(transport.calls, 0);
    drop(journal);
    assert!(ProviderEvidenceJournalV4::open_existing(
        &ready.path,
        ready.enrollment.clone(),
        &mut owner_budget()
    )
    .is_err());
}

#[test]
fn native_provider_v4_live_session_refuses_complete_record_rollback() {
    let mut ready = Ready::new(55);
    let mut journal = ready.journal();
    let initial_bytes = fs::read(&ready.path).unwrap();
    journal
        .observe_orphan_epoch(10, &mut owner_budget())
        .unwrap();
    // Preserve the file inode and a complete, valid prior record boundary.
    // Length/parser checks alone do not retain the already observed liability.
    let observed_bytes = fs::read(&ready.path).unwrap();
    fs::write(&ready.path, &initial_bytes).unwrap();
    let mut transport = Transport::new(&ready.path);
    let error = journal
        .reconcile(&mut ready.root, &mut transport, &mut owner_budget())
        .expect_err("an open session must reject a valid-prefix rollback");
    assert!(error
        .to_string()
        .contains("ROOT_PROVIDER_SESSION_HISTORY_CHANGED"));
    assert_eq!(transport.calls, 0);
    assert_eq!(fs::read(&ready.path).unwrap(), initial_bytes);
    fs::write(&ready.path, &observed_bytes).unwrap();
    assert!(journal
        .evidence(&mut owner_budget())
        .unwrap_err()
        .to_string()
        .contains("ROOT_PROVIDER_SESSION_FENCED"));
    fs::write(&ready.path, &initial_bytes).unwrap();
    drop(journal);

    // An in-memory observation cannot survive a common cold restore. The
    // unpinned reopen remains a negative control, not independent freshness.
    let cold = ready.reopen().evidence(&mut owner_budget()).unwrap();
    assert_eq!(cold.orphaned_at, None);
    assert!(!cold.authorization_granted());
    assert!(!cold.redispatch_permitted());
}

#[test]
fn native_provider_v4_live_session_refuses_same_length_history_substitution() {
    let ready = Ready::new(56);
    let mut journal = ready.journal();
    journal
        .observe_orphan_epoch(10, &mut owner_budget())
        .unwrap();
    let observed_bytes = fs::read(&ready.path).unwrap();
    let alternative_path = ready.h.directory.path().join("alternative.evidence");
    let mut alternative = ProviderEvidenceJournalV4::create(
        &alternative_path,
        ready.enrollment.clone(),
        &mut owner_budget(),
    )
    .unwrap();
    alternative
        .observe_orphan_epoch(11, &mut owner_budget())
        .unwrap();
    let alternative_bytes = fs::read(&alternative_path).unwrap();
    assert_eq!(alternative_bytes.len(), observed_bytes.len());
    assert_ne!(alternative_bytes, observed_bytes);
    fs::write(&ready.path, &alternative_bytes).unwrap();
    let error = journal
        .evidence(&mut owner_budget())
        .expect_err("length equality cannot replace the session's exact history");
    assert!(error
        .to_string()
        .contains("ROOT_PROVIDER_SESSION_HISTORY_CHANGED"));
    assert_eq!(fs::read(&ready.path).unwrap(), alternative_bytes);
    fs::write(&ready.path, &observed_bytes).unwrap();
    assert!(journal
        .observe_orphan_epoch(12, &mut owner_budget())
        .unwrap_err()
        .to_string()
        .contains("ROOT_PROVIDER_SESSION_FENCED"));
    assert_eq!(fs::read(&ready.path).unwrap(), observed_bytes);
}
