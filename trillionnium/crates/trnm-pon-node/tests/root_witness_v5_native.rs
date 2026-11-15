//! Real PQ signatures with separate in-process witness state. These are native
//! protocol/refusal controls, not independent physical custody or WAN evidence.
#![cfg(all(target_os = "linux", feature = "pq-root-v3"))]

#[path = "support/root_recovery_v3_fixture.rs"]
mod fixture;
use fixture::*;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::OnceLock;
use trnm_pon_node::root_recovery_v3::witnessed_v5::*;
use trnm_pon_node::root_recovery_v3::*;
use trnm_release_bundle::root_recovery_v3::{RootActionV3, RootEnvelopeV3, RootStatementV3};

fn witness_keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(Keys::generate)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WitnessFault {
    None,
    Unavailable,
    BeforeCas,
    AfterCas,
    WrongChallenge,
    WrongRequestDigest,
    WrongBinding,
    WrongSignature,
    WrongOutcome,
    ReplaceBudgetAfterCas,
    ReplaceBudgetErrorAfterCas,
    CancelAfterCas,
}

struct WitnessState {
    head: JournalHeadV3,
    calls: usize,
    cas_calls: usize,
    fault: WitnessFault,
    replacement: Option<PendingReplacement>,
}

/// A complete, differently signed pending transition produced by the real V3
/// owner. The callback substitutes it only after V5 has checked its first view.
struct PendingReplacement {
    path: PathBuf,
    anchor: Service,
    version: u64,
    previous_version: u64,
    previous_root: Vec<u8>,
    root: Vec<u8>,
    observed_at: u64,
    envelope: Vec<u8>,
    state: Vec<u8>,
}

impl PendingReplacement {
    fn from_owner(source: &Harness, target: &Harness) -> Self {
        let database = rusqlite::Connection::open(source.path()).unwrap();
        database
            .query_row(
                "SELECT version,previous_version,previous_root,root,observed_at,envelope,state FROM pending",
                [],
                |row| Ok(Self {
                    path: target.path(),
                    anchor: target.service.clone(),
                    version: row.get(0)?,
                    previous_version: row.get(1)?,
                    previous_root: row.get(2)?,
                    root: row.get(3)?,
                    observed_at: row.get(4)?,
                    envelope: row.get(5)?,
                    state: row.get(6)?,
                }),
            )
            .unwrap()
    }

    fn install(self) -> RootOwnerResultV3<()> {
        let database = rusqlite::Connection::open(&self.path).map_err(std::io::Error::other)?;
        let changed = database.execute(
            "UPDATE pending SET version=?1,previous_version=?2,previous_root=?3,root=?4,observed_at=?5,envelope=?6,state=?7 WHERE singleton=1",
            rusqlite::params![self.version, self.previous_version, self.previous_root, self.root, self.observed_at, self.envelope, self.state],
        ).map_err(std::io::Error::other)?;
        assert_eq!(changed, 1);
        self.anchor.state.borrow_mut().head = JournalHeadV3 {
            version: self.version,
            root: self.root.try_into().unwrap(),
        };
        Ok(())
    }
}

#[derive(Clone)]
struct WitnessService {
    policy: WitnessPolicyV5,
    state: Rc<RefCell<WitnessState>>,
}

impl RootWitnessTransportV5 for WitnessService {
    fn exchange(
        &mut self,
        envelope: WitnessEnvelopeV5,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedWitnessReceiptV5> {
        // The fixture uses the actual exported server-side authenticator.
        // Its pinned policy is never adopted from a request or root database.
        envelope.verify_writer(&self.policy, budget)?;
        let mut state = self.state.borrow_mut();
        state.calls += 1;
        if state.fault == WitnessFault::Unavailable {
            return Err(rejected("fixture witness unavailable"));
        }
        let request = &envelope.request;
        if request.target.is_none() {
            if let Some(replacement) = state.replacement.take() {
                replacement.install()?;
            }
        }
        let outcome = if let (Some(expected), Some(target)) = (request.expected, request.target) {
            state.cas_calls += 1;
            if state.fault == WitnessFault::BeforeCas {
                return Err(rejected("fixture witness disconnected before CAS"));
            }
            if state.head == expected {
                state.head = target;
                if state.fault == WitnessFault::AfterCas {
                    return Err(rejected("fixture witness lost acknowledgement"));
                }
                WitnessOutcomeV5::Advanced
            } else {
                WitnessOutcomeV5::Mismatch
            }
        } else {
            WitnessOutcomeV5::Current
        };
        let mut receipt = WitnessReceiptV5::for_request(request, state.head, outcome)?;
        match state.fault {
            WitnessFault::WrongChallenge => receipt.challenge[0] ^= 1,
            WitnessFault::WrongRequestDigest => receipt.request_digest[0] ^= 1,
            WitnessFault::WrongBinding => receipt.binding[0] ^= 1,
            WitnessFault::WrongOutcome => receipt.outcome = WitnessOutcomeV5::Mismatch,
            _ => {}
        }
        let mut approvals = witness_keys().quorum(&receipt.message()?);
        if state.fault == WitnessFault::WrongSignature {
            approvals[0].signature[0] ^= 1;
        }
        if request.target.is_some() {
            match state.fault {
                WitnessFault::ReplaceBudgetAfterCas | WitnessFault::ReplaceBudgetErrorAfterCas => {
                    *budget = owner_budget();
                }
                WitnessFault::CancelAfterCas => budget.cancel(),
                _ => {}
            }
            if state.fault == WitnessFault::ReplaceBudgetErrorAfterCas {
                return Err(rejected("fixture replaced budget and returned an error"));
            }
        }
        Ok(SignedWitnessReceiptV5 { receipt, approvals })
    }
}

struct WitnessHarness {
    root: Harness,
    witness: WitnessService,
}

impl WitnessHarness {
    fn new() -> Self {
        let root = Harness::new();
        let policy =
            WitnessPolicyV5::new(&root.enrollment, [91; 64], 1, witness_keys().roster.clone())
                .unwrap();
        let witness = WitnessService {
            policy,
            state: Rc::new(RefCell::new(WitnessState {
                head: root.enrollment.initial_head().unwrap(),
                calls: 0,
                cas_calls: 0,
                fault: WitnessFault::None,
                replacement: None,
            })),
        };
        Self { root, witness }
    }

    fn client(&self) -> RootWitnessV5 {
        RootWitnessV5::new(
            self.witness.policy.clone(),
            Writer { malformed: false },
            self.witness.clone(),
        )
    }

    fn create(&self) -> RootOwnerResultV3<WitnessedRootOwnerV5> {
        WitnessedRootOwnerV5::create(
            &self.root.path(),
            self.root.enrollment.clone(),
            Writer { malformed: false },
            self.root.service.clone(),
            self.client(),
            &mut owner_budget(),
        )
    }

    fn open(&self) -> RootOwnerResultV3<WitnessedRootOwnerV5> {
        WitnessedRootOwnerV5::open_existing(
            &self.root.path(),
            self.root.enrollment.clone(),
            Writer { malformed: false },
            self.root.service.clone(),
            self.client(),
            &mut owner_budget(),
        )
    }
}

fn append(owner: &mut WitnessedRootOwnerV5, nonce: u8) -> CommittedRootOperationV3 {
    let context = owner.context(&mut owner_budget()).unwrap();
    let envelope = fixtures().root.envelope(
        RootStatementV3 {
            scope: context.scope,
            generation: context.generation,
            sequence: context.last_sequence + 1,
            predecessor: context.predecessor,
            nonce: [nonce; 32],
            valid_from_unix: 100,
            expires_at_unix: 900,
            action: RootActionV3::Normal {
                intent: intent(nonce),
            },
        },
        None,
    );
    owner.apply(&envelope, 110, &mut owner_budget()).unwrap()
}

#[test]
fn native_witness_v5_complete_binding_and_role_separation_are_required() {
    let h = Harness::new();
    for roster in [
        &fixtures().root.roster,
        &fixtures().writer.roster,
        &fixtures().anchor.roster,
    ] {
        assert!(WitnessPolicyV5::new(&h.enrollment, [91; 64], 1, roster.clone()).is_err());
    }
    assert!(
        WitnessPolicyV5::new(&h.enrollment, [0; 64], 1, witness_keys().roster.clone()).is_err()
    );
    assert!(
        WitnessPolicyV5::new(&h.enrollment, [91; 64], 0, witness_keys().roster.clone()).is_err()
    );
    let base =
        WitnessPolicyV5::new(&h.enrollment, [91; 64], 1, witness_keys().roster.clone()).unwrap();
    for (domain, epoch) in [([92; 64], 1), ([91; 64], 2)] {
        let changed =
            WitnessPolicyV5::new(&h.enrollment, domain, epoch, witness_keys().roster.clone())
                .unwrap();
        assert_ne!(changed.binding(), base.binding());
    }
    let mut changed_policy = fixtures().root.policy();
    changed_policy.expires_at_unix -= 1;
    let changed_enrollment = JournalEnrollmentV3::new(
        domain(),
        changed_policy,
        100,
        fixtures().writer.roster.clone(),
        fixtures().anchor.roster.clone(),
    )
    .unwrap();
    assert_eq!(changed_enrollment.scope(), h.enrollment.scope());
    let changed = WitnessPolicyV5::new(
        &changed_enrollment,
        [91; 64],
        1,
        witness_keys().roster.clone(),
    )
    .unwrap();
    assert_ne!(
        changed.enrollment_commitment(),
        base.enrollment_commitment()
    );
    assert_ne!(changed.binding(), base.binding());
    assert!(!h.path().exists());
}

#[test]
fn native_witness_v5_success_is_witnessed_before_pending_is_completed() {
    let h = WitnessHarness::new();
    let mut owner = h.create().unwrap();
    let operation = append(&mut owner, 61);
    assert_eq!(h.root.pending(), 0);
    assert_eq!(h.witness.state.borrow().head, operation.head);
    assert_eq!(h.witness.state.borrow().cas_calls, 1);
    {
        let observation = owner
            .observe_current_intent(operation.operation_id, 111, &mut owner_budget())
            .unwrap();
        assert_eq!(observation.observed_head(), operation.head);
        assert_eq!(observation.witness_binding(), h.witness.policy.binding());
    }
    drop(owner);
    assert_eq!(
        h.open().unwrap().context(&mut owner_budget()).unwrap().head,
        operation.head
    );
}

#[test]
fn native_witness_v5_surviving_witness_refuses_common_owner_anchor_restore() {
    let h = WitnessHarness::new();
    let mut owner = h.create().unwrap();
    let first = append(&mut owner, 49);
    let old_owner = std::fs::read(h.root.path()).unwrap();
    let second = append(&mut owner, 50);
    drop(owner);
    std::fs::write(h.root.path(), &old_owner).unwrap();
    h.root.service.state.borrow_mut().head = first.head;
    assert_eq!(h.witness.state.borrow().head, second.head);
    let anchor_calls = h.root.service.state.borrow().calls;
    let witness_cas = h.witness.state.borrow().cas_calls;
    assert_eq!(
        h.open().err().unwrap().to_string(),
        "ROOT_OWNER_RECOVERY_FLOOR_NOT_IN_SIGNED_HISTORY"
    );
    assert_eq!(h.root.service.state.borrow().calls, anchor_calls);
    assert_eq!(h.witness.state.borrow().cas_calls, witness_cas);
    assert_eq!(std::fs::read(h.root.path()).unwrap(), old_owner);
}

#[test]
fn native_witness_v5_restoring_every_authority_remains_an_explicit_counterexample() {
    let h = WitnessHarness::new();
    let mut owner = h.create().unwrap();
    let first = append(&mut owner, 62);
    let snapshot = std::fs::read(h.root.path()).unwrap();
    let second = append(&mut owner, 63);
    assert!(second.head.version > first.head.version);
    drop(owner);
    std::fs::write(h.root.path(), snapshot).unwrap();
    h.root.service.state.borrow_mut().head = first.head;
    h.witness.state.borrow_mut().head = first.head;
    let mut restored = h.open().unwrap();
    assert_eq!(
        restored.context(&mut owner_budget()).unwrap().head,
        first.head
    );
    assert!(restored
        .observe_current_intent(first.operation_id, 112, &mut owner_budget())
        .is_ok());
    // A fresh signature from a restored witness cannot reveal its lost history.
    // This PASS preserves the limit; it is not a physical non-rollback result.
}

#[test]
fn native_witness_v5_unavailable_witness_has_no_static_floor_fallback() {
    let h = WitnessHarness::new();
    h.witness.state.borrow_mut().fault = WitnessFault::Unavailable;
    assert!(h.create().is_err());
    assert!(!h.root.path().exists());
    assert_eq!(h.root.service.state.borrow().calls, 0);
}

#[test]
fn native_witness_v5_signed_response_must_bind_the_complete_fresh_request() {
    for fault in [
        WitnessFault::WrongChallenge,
        WitnessFault::WrongRequestDigest,
        WitnessFault::WrongBinding,
    ] {
        let h = WitnessHarness::new();
        h.witness.state.borrow_mut().fault = fault;
        assert_eq!(
            h.create().err().unwrap().to_string(),
            "ROOT_WITNESS_V5_COMPLETE_REQUEST_BINDING"
        );
        assert!(!h.root.path().exists());
        assert_eq!(h.root.service.state.borrow().calls, 0);
    }
}

#[test]
fn native_witness_v5_wrong_signature_and_outcome_are_refused() {
    for fault in [WitnessFault::WrongSignature, WitnessFault::WrongOutcome] {
        let h = WitnessHarness::new();
        h.witness.state.borrow_mut().fault = fault;
        assert!(h.create().is_err());
        assert!(!h.root.path().exists());
    }
}

#[test]
fn native_witness_v5_another_recovery_epoch_cannot_use_the_same_service_pin() {
    let h = WitnessHarness::new();
    let changed = WitnessPolicyV5::new(
        &h.root.enrollment,
        [91; 64],
        2,
        witness_keys().roster.clone(),
    )
    .unwrap();
    let witness = RootWitnessV5::new(changed, Writer { malformed: false }, h.witness.clone());
    let result = WitnessedRootOwnerV5::create(
        &h.root.path(),
        h.root.enrollment.clone(),
        Writer { malformed: false },
        h.root.service.clone(),
        witness,
        &mut owner_budget(),
    );
    assert_eq!(
        result.err().unwrap().to_string(),
        "ROOT_WITNESS_V5_REQUEST_BINDING"
    );
    assert!(!h.root.path().exists());
    assert_eq!(h.witness.state.borrow().calls, 0);
}

#[test]
fn native_witness_v5_lost_ack_retains_pending_and_resumes_without_another_cas() {
    let h = WitnessHarness::new();
    let mut owner = h.create().unwrap();
    h.witness.state.borrow_mut().fault = WitnessFault::AfterCas;
    assert!(owner
        .apply(&normal(&state(), 64), 110, &mut owner_budget())
        .is_err());
    assert_eq!(h.root.pending(), 1);
    let target = h.witness.state.borrow().head;
    assert_eq!(target, h.root.service.state.borrow().head);
    let witness_cas = h.witness.state.borrow().cas_calls;
    let anchor_cas = h.root.service.state.borrow().cas_calls;
    assert!(owner.context(&mut owner_budget()).is_err());
    drop(owner);
    h.witness.state.borrow_mut().fault = WitnessFault::None;
    let mut reopened = h.open().unwrap();
    assert_eq!(
        reopened.resume_pending(&mut owner_budget()).unwrap(),
        target
    );
    assert_eq!(h.root.pending(), 0);
    assert_eq!(h.witness.state.borrow().cas_calls, witness_cas);
    assert_eq!(h.root.service.state.borrow().cas_calls, anchor_cas);
    assert_eq!(reopened.context(&mut owner_budget()).unwrap().head, target);
}

#[test]
fn native_witness_v5_pre_cas_disconnect_retries_only_the_verified_witness_transition() {
    let h = WitnessHarness::new();
    let mut owner = h.create().unwrap();
    let before = h.witness.state.borrow().head;
    h.witness.state.borrow_mut().fault = WitnessFault::BeforeCas;
    assert!(owner
        .apply(&normal(&state(), 65), 110, &mut owner_budget())
        .is_err());
    assert_eq!(h.root.pending(), 1);
    assert_eq!(h.witness.state.borrow().head, before);
    let target = h.root.service.state.borrow().head;
    let anchor_cas = h.root.service.state.borrow().cas_calls;
    let witness_cas = h.witness.state.borrow().cas_calls;
    drop(owner);
    h.witness.state.borrow_mut().fault = WitnessFault::None;
    let mut reopened = h.open().unwrap();
    assert_eq!(
        reopened.resume_pending(&mut owner_budget()).unwrap(),
        target
    );
    assert_eq!(h.root.pending(), 0);
    assert_eq!(h.root.service.state.borrow().cas_calls, anchor_cas);
    assert_eq!(h.witness.state.borrow().cas_calls, witness_cas + 1);
    assert_eq!(h.witness.state.borrow().head, target);
}

#[test]
fn native_witness_v5_corrupt_pending_never_advances_the_witness() {
    for corrupt_signature in [false, true] {
        let h = WitnessHarness::new();
        let mut owner = h.create().unwrap();
        h.witness.state.borrow_mut().fault = WitnessFault::BeforeCas;
        assert!(owner
            .apply(&normal(&state(), 66), 110, &mut owner_budget())
            .is_err());
        drop(owner);
        let database = rusqlite::Connection::open(h.root.path()).unwrap();
        if corrupt_signature {
            let bytes: Vec<u8> = database
                .query_row("SELECT envelope FROM pending", [], |row| row.get(0))
                .unwrap();
            let mut envelope = RootEnvelopeV3::decode(&bytes).unwrap();
            envelope.approvals[0].signature[0] ^= 1;
            database
                .execute(
                    "UPDATE pending SET envelope=?1",
                    [envelope.encode().unwrap()],
                )
                .unwrap();
        } else {
            database
                .execute("UPDATE pending SET state=zeroblob(length(state))", [])
                .unwrap();
        }
        drop(database);
        let before = std::fs::read(h.root.path()).unwrap();
        let witness_cas = h.witness.state.borrow().cas_calls;
        let head = h.witness.state.borrow().head;
        h.witness.state.borrow_mut().fault = WitnessFault::None;
        assert!(h.open().is_err());
        assert_eq!(h.root.pending(), 1);
        assert_eq!(h.witness.state.borrow().cas_calls, witness_cas);
        assert_eq!(h.witness.state.borrow().head, head);
        assert_eq!(std::fs::read(h.root.path()).unwrap(), before);
    }
}

#[test]
fn native_witness_v5_callback_budget_replacement_and_cancellation_remain_fenced() {
    for fault in [
        WitnessFault::ReplaceBudgetAfterCas,
        WitnessFault::ReplaceBudgetErrorAfterCas,
        WitnessFault::CancelAfterCas,
    ] {
        let h = WitnessHarness::new();
        let mut owner = h.create().unwrap();
        h.witness.state.borrow_mut().fault = fault;
        let error = owner
            .apply(&normal(&state(), 67), 110, &mut owner_budget())
            .err()
            .unwrap();
        if matches!(
            fault,
            WitnessFault::ReplaceBudgetAfterCas | WitnessFault::ReplaceBudgetErrorAfterCas
        ) {
            assert_eq!(error.to_string(), "ROOT_OWNER_CALLBACK_REPLACED_BUDGET");
        }
        assert_eq!(h.root.pending(), 1);
        assert!(owner.context(&mut owner_budget()).is_err());
        drop(owner);
        h.witness.state.borrow_mut().fault = WitnessFault::None;
        assert!(h
            .open()
            .unwrap()
            .resume_pending(&mut owner_budget())
            .is_ok());
    }
}

#[test]
fn native_witness_v5_context_and_intent_recheck_live_witness_and_latch_failure() {
    for (observe_intent, equivocate) in [(false, false), (true, false), (false, true), (true, true)]
    {
        let h = WitnessHarness::new();
        let mut owner = h.create().unwrap();
        let initial = h.root.enrollment.initial_head().unwrap();
        let committed = append(&mut owner, 68);
        let mut conflicting = committed.head;
        conflicting.root[0] ^= 1;
        h.witness.state.borrow_mut().head = if equivocate { conflicting } else { initial };
        let error = if observe_intent {
            owner
                .observe_current_intent(committed.operation_id, 111, &mut owner_budget())
                .err()
                .unwrap()
        } else {
            owner.context(&mut owner_budget()).err().unwrap()
        };
        assert_eq!(
            error.to_string(),
            "ROOT_WITNESS_V5_REGRESSION_OR_EQUIVOCATION"
        );
        h.witness.state.borrow_mut().head = committed.head;
        assert_eq!(
            owner
                .context(&mut owner_budget())
                .err()
                .unwrap()
                .to_string(),
            "ROOT_WITNESS_V5_OWNER_FENCED"
        );
    }
}

#[test]
fn native_witness_v5_rotation_cannot_reuse_witness_keys() {
    let h = WitnessHarness::new();
    let mut owner = h.create().unwrap();
    let envelope = fixtures().root.envelope(
        statement(
            &state(),
            69,
            RootActionV3::Rotate {
                next: witness_keys().policy(),
            },
        ),
        Some(witness_keys()),
    );
    assert_eq!(
        owner
            .apply(&envelope, 110, &mut owner_budget())
            .err()
            .unwrap()
            .to_string(),
        "ROOT_WITNESS_V5_CROSS_ROLE_ROOT_KEY"
    );
    assert_eq!(h.root.pending(), 0);
    assert_eq!(h.root.service.state.borrow().cas_calls, 0);
    assert_eq!(h.witness.state.borrow().cas_calls, 0);
}

#[test]
fn native_witness_v5_open_checks_retained_root_key_roles() {
    let h = WitnessHarness::new();
    let mut legacy = h.root.create();
    let envelope = fixtures().root.envelope(
        statement(
            &state(),
            70,
            RootActionV3::Rotate {
                next: witness_keys().policy(),
            },
        ),
        Some(witness_keys()),
    );
    let operation = legacy.apply(&envelope, 110, &mut owner_budget()).unwrap();
    drop(legacy);
    h.witness.state.borrow_mut().head = operation.head;
    assert_eq!(
        h.open().err().unwrap().to_string(),
        "ROOT_WITNESS_V5_CROSS_ROLE_ROOT_KEY"
    );
    assert_eq!(h.witness.state.borrow().cas_calls, 0);
}

#[test]
fn native_witness_v5_unwitnessed_v3_commit_cannot_be_promoted_from_an_ancestor_floor() {
    let h = WitnessHarness::new();
    let mut legacy = h.root.create();
    let committed = legacy
        .apply(&normal(&state(), 71), 110, &mut owner_budget())
        .unwrap();
    drop(legacy);
    assert_eq!(h.root.pending(), 0);
    assert_ne!(h.witness.state.borrow().head, committed.head);
    assert_eq!(
        h.open().err().unwrap().to_string(),
        "ROOT_WITNESS_V5_CURRENT_HEAD"
    );
    assert_eq!(h.witness.state.borrow().cas_calls, 0);
}

#[test]
fn native_witness_v5_changed_signed_pending_and_anchor_cannot_bypass_role_snapshot() {
    let h = WitnessHarness::new();
    let mut owner = h.create().unwrap();
    h.witness.state.borrow_mut().fault = WitnessFault::BeforeCas;
    assert!(owner
        .apply(&normal(&state(), 72), 110, &mut owner_budget())
        .is_err());
    let guarded_target = h.root.service.state.borrow().head;
    drop(owner);
    h.witness.state.borrow_mut().fault = WitnessFault::None;
    let mut reopened = h.open().unwrap();

    // Obtain a different, genuinely signed and staged transition at the exact
    // same predecessor. V3 permits these next-root keys, while V5 forbids their
    // witness-role reuse. No synthetic invalid signature is involved here.
    let other = Harness::new();
    assert_eq!(
        other.enrollment.initial_head().unwrap(),
        h.root.enrollment.initial_head().unwrap()
    );
    let mut legacy = other.create();
    other.service.state.borrow_mut().fault = Fault::AfterCas;
    let rotation = fixtures().root.envelope(
        statement(
            &state(),
            73,
            RootActionV3::Rotate {
                next: witness_keys().policy(),
            },
        ),
        Some(witness_keys()),
    );
    assert!(legacy.apply(&rotation, 110, &mut owner_budget()).is_err());
    let replacement_target = other.service.state.borrow().head;
    assert_ne!(replacement_target, guarded_target);
    drop(legacy);
    let replacement = PendingReplacement::from_owner(&other, &h.root);
    let witness_cas = h.witness.state.borrow().cas_calls;
    let witness_head = h.witness.state.borrow().head;
    h.witness.state.borrow_mut().replacement = Some(replacement);

    // The next witness read is after the atomic signature/role snapshot. Its
    // callback replaces both pending and original anchor with the signed Q.
    // The inner owner can authenticate Q, but the V5 ACK must still match P.
    assert_eq!(
        reopened
            .resume_pending(&mut owner_budget())
            .err()
            .unwrap()
            .to_string(),
        "ROOT_WITNESS_V5_PENDING_SNAPSHOT_CHANGED",
    );
    assert_eq!(h.root.service.state.borrow().head, replacement_target);
    assert_eq!(h.root.pending(), 1);
    assert_eq!(h.witness.state.borrow().head, witness_head);
    assert_eq!(h.witness.state.borrow().cas_calls, witness_cas);
    assert!(reopened.context(&mut owner_budget()).is_err());
}
