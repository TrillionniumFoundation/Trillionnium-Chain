//! Real dual-family signatures with a same-host fixture authority. These tests
//! deliberately retain the complete-owner-plus-anchor rollback counterexample.
#![cfg(all(target_os = "linux", feature = "pq-root-v3"))]

use openssl::{
    asn1::Asn1Object,
    pkey::{Id, PKey, Private},
    pkey_ctx::PkeyCtx,
    sign::Signer,
};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::rc::Rc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use trnm_crypto_primitives::pq_root_v3::{
    possession_message_v3, DualFamilyRosterV3, RootPublicKeyV3, RootSignatureV3, RootSuiteV3,
    VerificationBudgetV3,
};
use trnm_pon_node::root_recovery_v3::*;
use trnm_release_bundle::root_recovery_v3::{
    DigestV3, ReleaseIntentV3, ReleaseUseV3, RootActionV3, RootEnvelopeV3, RootPolicyV3,
    RootStateV3, RootStatementV3,
};

fn rejected(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

struct Keys {
    roster: DualFamilyRosterV3,
    secret: BTreeMap<DigestV3, PKey<Private>>,
}
impl Keys {
    fn generate() -> Self {
        assert!(
            openssl::version::number() >= 0x3050_0000,
            "actual OpenSSL 3.5+ required"
        );
        let mut keys = Vec::new();
        let mut secret = BTreeMap::new();
        for (suite, oid) in [
            (RootSuiteV3::MlDsa87, "2.16.840.1.101.3.4.3.19"),
            (RootSuiteV3::SlhDsaSha2_256s, "2.16.840.1.101.3.4.3.24"),
        ] {
            for _ in 0..3 {
                let object = Asn1Object::from_str(oid).unwrap();
                let mut generation = PkeyCtx::new_id(Id::from_raw(object.nid().as_raw())).unwrap();
                generation.keygen_init().unwrap();
                let private = generation.keygen().unwrap();
                let public = RootPublicKeyV3 {
                    suite,
                    spki: private.public_key_to_der().unwrap(),
                };
                secret.insert(public.id().unwrap(), private);
                keys.push(public);
            }
        }
        Self {
            roster: DualFamilyRosterV3::from_keys(keys).unwrap(),
            secret,
        }
    }
    fn sign(&self, id: DigestV3, message: &[u8]) -> RootSignatureV3 {
        let mut signer = Signer::new_without_digest(&self.secret[&id]).unwrap();
        RootSignatureV3 {
            signer: id,
            signature: signer.sign_oneshot_to_vec(message).unwrap(),
        }
    }
    fn quorum(&self, message: &[u8]) -> Vec<RootSignatureV3> {
        RootSuiteV3::ALL
            .into_iter()
            .flat_map(|suite| {
                self.roster
                    .keys()
                    .iter()
                    .filter(move |key| key.suite == suite)
                    .take(2)
            })
            .map(|key| self.sign(key.id().unwrap(), message))
            .collect()
    }
    fn policy(&self) -> RootPolicyV3 {
        RootPolicyV3 {
            roster: self.roster.clone(),
            expires_at_unix: 1000,
        }
    }
    fn envelope(&self, statement: RootStatementV3, successor: Option<&Keys>) -> RootEnvelopeV3 {
        let approvals = self.quorum(&statement.signing_message().unwrap());
        let successor_possessions = successor.map_or_else(Vec::new, |next| {
            next.roster
                .key_ids()
                .into_iter()
                .map(|id| {
                    next.sign(
                        id,
                        &possession_message_v3(&statement.encode().unwrap(), &next.roster, id)
                            .unwrap(),
                    )
                })
                .collect()
        });
        RootEnvelopeV3 {
            statement,
            approvals,
            successor_possessions,
        }
    }
}
struct Fixtures {
    root: Keys,
    next: Keys,
    writer: Keys,
    anchor: Keys,
}
fn fixtures() -> &'static Fixtures {
    static FIXTURE: OnceLock<Fixtures> = OnceLock::new();
    FIXTURE.get_or_init(|| Fixtures {
        root: Keys::generate(),
        next: Keys::generate(),
        writer: Keys::generate(),
        anchor: Keys::generate(),
    })
}
fn owner_budget() -> OwnerBudgetV3 {
    let until = Instant::now() + Duration::from_secs(120);
    OwnerBudgetV3::new(
        VerificationBudgetV3::with_deadline(4096, until).unwrap(),
        until,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap()
}
fn domain() -> JournalDomainV3 {
    JournalDomainV3::new([17; 32], [18; 32], [19; 32]).unwrap()
}
fn state() -> RootStateV3 {
    RootStateV3::bootstrap(domain().scope(), fixtures().root.policy(), 100).unwrap()
}
fn intent(attempt: u8) -> ReleaseIntentV3 {
    ReleaseIntentV3::from_bytes(
        ReleaseUseV3::Install,
        b"complete bundle",
        b"complete launch contract",
        b"held actual executable",
        [attempt; 32],
    )
    .unwrap()
}
fn statement(current: &RootStateV3, nonce: u8, action: RootActionV3) -> RootStatementV3 {
    RootStatementV3 {
        scope: current.scope(),
        generation: current.generation(),
        sequence: current.sequence() + 1,
        predecessor: current.checkpoint(),
        nonce: [nonce; 32],
        valid_from_unix: 100,
        expires_at_unix: 900,
        action,
    }
}
fn normal(current: &RootStateV3, nonce: u8) -> RootEnvelopeV3 {
    fixtures().root.envelope(
        statement(
            current,
            nonce,
            RootActionV3::Normal {
                intent: intent(nonce),
            },
        ),
        None,
    )
}

#[test]
fn native_owner_v3_domain_binds_each_independent_identity_without_zero_fallback() {
    let pinned = domain();
    assert_eq!(pinned.network(), [17; 32]);
    assert_eq!(pinned.genesis(), [18; 32]);
    assert_eq!(pinned.owner(), [19; 32]);
    for (network, genesis, owner) in [
        ([0; 32], [18; 32], [19; 32]),
        ([17; 32], [0; 32], [19; 32]),
        ([17; 32], [18; 32], [0; 32]),
    ] {
        assert!(JournalDomainV3::new(network, genesis, owner).is_err());
    }
    for changed in [
        JournalDomainV3::new([20; 32], [18; 32], [19; 32]).unwrap(),
        JournalDomainV3::new([17; 32], [20; 32], [19; 32]).unwrap(),
        JournalDomainV3::new([17; 32], [18; 32], [20; 32]).unwrap(),
        JournalDomainV3::new([18; 32], [17; 32], [19; 32]).unwrap(),
    ] {
        assert_ne!(changed.scope(), pinned.scope());
    }
}

struct Writer {
    malformed: bool,
}
impl RootWriterSignerV3 for Writer {
    fn sign(
        &mut self,
        message: &[u8],
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Vec<RootSignatureV3>> {
        budget.check()?;
        let mut signatures = fixtures().writer.quorum(message);
        if self.malformed {
            signatures[0].signature[0] ^= 1;
        }
        budget.check()?;
        Ok(signatures)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    None,
    BeforeCas,
    AfterCas,
    WrongChallenge,
    WrongSignature,
    CancelAfterCas,
    ReplaceBudgetAfterCas,
}
struct ServiceState {
    head: JournalHeadV3,
    calls: usize,
    cas_calls: usize,
    fault: Fault,
    reset_cancellation: Option<Arc<AtomicBool>>,
}
#[derive(Clone)]
struct Service {
    state: Rc<RefCell<ServiceState>>,
    scope: DigestV3,
}
impl RootAnchorTransportV3 for Service {
    fn exchange(
        &mut self,
        request: AnchorEnvelopeV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedAnchorReceiptV3> {
        // The fixture uses the exact exported anchor-side authenticator. Its
        // separate enrollment pins cannot be supplied by this request.
        request.verify_writer(self.scope, &fixtures().writer.roster, budget)?;
        let mut state = self.state.borrow_mut();
        state.calls += 1;
        let outcome = if let (Some(expected), Some(target)) =
            (request.request.expected, request.request.target)
        {
            state.cas_calls += 1;
            if state.fault == Fault::BeforeCas {
                return Err(rejected("fixture disconnect before CAS"));
            }
            if expected != state.head {
                AnchorOutcomeV3::Mismatch
            } else {
                state.head = target;
                if state.fault == Fault::AfterCas {
                    return Err(rejected("fixture lost reply after CAS"));
                }
                if state.fault == Fault::CancelAfterCas {
                    budget.cancel();
                    if let Some(external) = &state.reset_cancellation {
                        external.store(false, Ordering::Release);
                    }
                }
                AnchorOutcomeV3::Advanced
            }
        } else {
            AnchorOutcomeV3::Current
        };
        let mut receipt = AnchorReceiptV3::for_request(&request.request, state.head, outcome)?;
        if state.fault == Fault::WrongChallenge {
            receipt.challenge[0] ^= 1;
        }
        let mut approvals = fixtures().anchor.quorum(&receipt.message()?);
        if state.fault == Fault::WrongSignature {
            approvals[0].signature[0] ^= 1;
        }
        if state.fault == Fault::ReplaceBudgetAfterCas && request.request.target.is_some() {
            *budget = owner_budget();
        }
        Ok(SignedAnchorReceiptV3 { receipt, approvals })
    }
}

struct Harness {
    directory: TempDir,
    enrollment: JournalEnrollmentV3,
    service: Service,
}
impl Harness {
    fn new() -> Self {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let enrollment = JournalEnrollmentV3::new(
            domain(),
            fixtures().root.policy(),
            100,
            fixtures().writer.roster.clone(),
            fixtures().anchor.roster.clone(),
        )
        .unwrap();
        let service = Service {
            scope: enrollment.scope(),
            state: Rc::new(RefCell::new(ServiceState {
                head: enrollment.initial_head().unwrap(),
                calls: 0,
                cas_calls: 0,
                fault: Fault::None,
                reset_cancellation: None,
            })),
        };
        Self {
            directory,
            enrollment,
            service,
        }
    }
    fn path(&self) -> std::path::PathBuf {
        self.directory.path().join("root.sqlite")
    }
    fn create(&self) -> RootOwnerV3 {
        RootOwnerV3::create(
            &self.path(),
            self.enrollment.clone(),
            Writer { malformed: false },
            self.service.clone(),
            &mut owner_budget(),
        )
        .unwrap()
    }
    fn open(&self) -> RootOwnerResultV3<RootOwnerV3> {
        RootOwnerV3::open_existing(
            &self.path(),
            self.enrollment.clone(),
            Writer { malformed: false },
            self.service.clone(),
            &mut owner_budget(),
        )
    }
    fn pending(&self) -> usize {
        rusqlite::Connection::open(self.path())
            .unwrap()
            .query_row("SELECT COUNT(*) FROM pending", [], |row| row.get(0))
            .unwrap()
    }
}

#[test]
fn native_owner_v3_real_signed_append_reopen_and_exact_intent_observation() {
    let h = Harness::new();
    let mut owner = h.create();
    let operation = normal(&state(), 1);
    let committed = owner.apply(&operation, 110, &mut owner_budget()).unwrap();
    assert_eq!(committed.head.version, 1);
    assert_eq!(h.pending(), 0);
    drop(owner);
    let mut reopened = h.open().unwrap();
    let context = reopened.context(&mut owner_budget()).unwrap();
    assert_eq!(context.last_sequence, 1);
    assert_eq!(context.head, committed.head);
    let observed = reopened
        .observe_current_intent(committed.operation_id, 111, &mut owner_budget())
        .unwrap();
    assert!(observed.intent().matches_bytes(
        b"complete bundle",
        b"complete launch contract",
        b"held actual executable"
    ));
    assert!(!observed.intent().matches_bytes(
        b"complete bundle",
        b"changed command",
        b"held actual executable"
    ));
}

#[test]
fn native_owner_v3_replay_preserves_nonce_and_refuses_second_exact_operation() {
    let h = Harness::new();
    let operation = normal(&state(), 2);
    let mut owner = h.create();
    owner.apply(&operation, 110, &mut owner_budget()).unwrap();
    drop(owner);
    let mut reopened = h.open().unwrap();
    let before = h.service.state.borrow().head;
    assert!(reopened
        .apply(&operation, 111, &mut owner_budget())
        .is_err());
    drop(reopened);
    let mut current = state();
    current
        .apply(&operation, 110, &mut VerificationBudgetV3::new(64).unwrap())
        .unwrap();
    let changed = fixtures().root.envelope(
        statement(&current, 2, RootActionV3::Normal { intent: intent(22) }),
        None,
    );
    let error = h
        .open()
        .unwrap()
        .apply(&changed, 111, &mut owner_budget())
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("refused: Nonce"),
        "fresh predecessor and valid new signatures still cannot reuse a persisted nonce: {error}"
    );
    assert_eq!(h.service.state.borrow().head, before);
    assert_eq!(h.pending(), 0);
}

#[test]
fn native_owner_v3_lost_successful_cas_reply_requires_explicit_exact_completion() {
    let h = Harness::new();
    let mut owner = h.create();
    let operation = normal(&state(), 3);
    h.service.state.borrow_mut().fault = Fault::AfterCas;
    assert!(owner.apply(&operation, 110, &mut owner_budget()).is_err());
    assert_eq!(h.pending(), 1);
    assert_eq!(h.service.state.borrow().head.version, 1);
    assert!(owner.context(&mut owner_budget()).is_err());
    drop(owner);
    h.service.state.borrow_mut().fault = Fault::None;
    let mut reopened = h.open().unwrap();
    assert_eq!(
        h.pending(),
        1,
        "open does not promote pending automatically"
    );
    let calls_before = h.service.state.borrow().cas_calls;
    let head = reopened.resume_pending(&mut owner_budget()).unwrap();
    assert_eq!(head.version, 1);
    assert_eq!(h.pending(), 0);
    assert_eq!(
        h.service.state.borrow().cas_calls,
        calls_before,
        "recovery never resubmits CAS"
    );
    reopened
        .observe_current_intent(
            operation.statement.operation_id().unwrap(),
            111,
            &mut owner_budget(),
        )
        .unwrap();
}

#[test]
fn native_owner_v3_unadvanced_anchor_cannot_clear_pending_or_retry() {
    let h = Harness::new();
    let mut owner = h.create();
    h.service.state.borrow_mut().fault = Fault::BeforeCas;
    assert!(owner
        .apply(&normal(&state(), 4), 110, &mut owner_budget())
        .is_err());
    assert_eq!(h.pending(), 1);
    assert_eq!(h.service.state.borrow().head.version, 0);
    drop(owner);
    h.service.state.borrow_mut().fault = Fault::None;
    assert!(h.open().is_err());
    assert_eq!(h.pending(), 1);
    assert!(RootOwnerV3::create(
        &h.path(),
        h.enrollment.clone(),
        Writer { malformed: false },
        h.service.clone(),
        &mut owner_budget()
    )
    .is_err());
}

#[test]
fn native_owner_v3_corrupt_pending_state_cannot_promote_even_after_real_cas() {
    let h = Harness::new();
    let mut owner = h.create();
    h.service.state.borrow_mut().fault = Fault::AfterCas;
    assert!(owner
        .apply(&normal(&state(), 5), 110, &mut owner_budget())
        .is_err());
    drop(owner);
    let foreign = rusqlite::Connection::open(h.path()).unwrap();
    foreign
        .execute("UPDATE pending SET state=zeroblob(length(state))", [])
        .unwrap();
    drop(foreign);
    h.service.state.borrow_mut().fault = Fault::None;
    let mut reopened = h.open().unwrap();
    assert!(reopened.resume_pending(&mut owner_budget()).is_err());
    assert_eq!(h.pending(), 1);
}

#[test]
fn native_owner_v3_retained_external_anchor_refuses_whole_local_rollback() {
    let h = Harness::new();
    let mut owner = h.create();
    let before = fs::read(h.path()).unwrap();
    owner
        .apply(&normal(&state(), 6), 110, &mut owner_budget())
        .unwrap();
    drop(owner);
    fs::write(h.path(), before).unwrap();
    assert!(h.open().is_err());
    assert_eq!(h.service.state.borrow().head.version, 1);
}

#[test]
fn native_owner_v3_co_restored_owner_and_anchor_counterexample_remains_accepted() {
    let h = Harness::new();
    let mut owner = h.create();
    let first = normal(&state(), 7);
    let first_commit = owner.apply(&first, 110, &mut owner_budget()).unwrap();
    let snapshot = fs::read(h.path()).unwrap();
    let mut kernel = state();
    kernel
        .apply(&first, 110, &mut VerificationBudgetV3::new(64).unwrap())
        .unwrap();
    owner
        .apply(&normal(&kernel, 8), 111, &mut owner_budget())
        .unwrap();
    drop(owner);
    fs::write(h.path(), snapshot).unwrap();
    h.service.state.borrow_mut().head = first_commit.head;
    let mut restored = h.open().unwrap();
    // Fresh real signatures cannot identify a rollback of every retained source
    // of currentness. This accepted observation is the explicit counterexample.
    assert!(restored
        .observe_current_intent(first_commit.operation_id, 112, &mut owner_budget())
        .is_ok());
}

#[test]
fn native_owner_v3_wrong_enrollment_scope_and_service_aliases_are_refused() {
    let h = Harness::new();
    assert!(JournalEnrollmentV3::new(
        domain(),
        fixtures().writer.policy(),
        100,
        fixtures().writer.roster.clone(),
        fixtures().anchor.roster.clone()
    )
    .is_err());
    assert!(JournalEnrollmentV3::new(
        domain(),
        fixtures().root.policy(),
        100,
        fixtures().anchor.roster.clone(),
        fixtures().anchor.roster.clone()
    )
    .is_err());
    let owner = h.create();
    drop(owner);
    let wrong = JournalEnrollmentV3::new(
        JournalDomainV3::new([18; 32], [18; 32], [19; 32]).unwrap(),
        fixtures().root.policy(),
        100,
        fixtures().writer.roster.clone(),
        fixtures().anchor.roster.clone(),
    )
    .unwrap();
    let calls = h.service.state.borrow().calls;
    assert!(RootOwnerV3::open_existing(
        &h.path(),
        wrong,
        Writer { malformed: false },
        h.service.clone(),
        &mut owner_budget()
    )
    .is_err());
    assert_eq!(
        h.service.state.borrow().calls,
        calls,
        "enrollment mismatch rejects before transport"
    );
}

#[test]
fn native_owner_v3_successor_cannot_reuse_an_anchor_or_writer_key() {
    let h = Harness::new();
    let mut owner = h.create();
    let action = RootActionV3::Rotate {
        next: fixtures().anchor.policy(),
    };
    let operation = fixtures()
        .root
        .envelope(statement(&state(), 9, action), Some(&fixtures().anchor));
    assert!(owner.apply(&operation, 110, &mut owner_budget()).is_err());
    assert_eq!(h.pending(), 0);
    assert_eq!(h.service.state.borrow().head.version, 0);
}

#[test]
fn native_owner_v3_last_observation_rechecks_persisted_revocation_and_rotation() {
    for rotate in [false, true] {
        let h = Harness::new();
        let mut owner = h.create();
        let first = normal(&state(), 10);
        let operation = owner
            .apply(&first, 110, &mut owner_budget())
            .unwrap()
            .operation_id;
        let mut current = state();
        current
            .apply(&first, 110, &mut VerificationBudgetV3::new(64).unwrap())
            .unwrap();
        let action = if rotate {
            RootActionV3::Rotate {
                next: fixtures().next.policy(),
            }
        } else {
            RootActionV3::Revoke {
                keys: vec![first.approvals[0].signer],
            }
        };
        let transition = fixtures().root.envelope(
            statement(&current, 11, action),
            rotate.then_some(&fixtures().next),
        );
        owner.apply(&transition, 111, &mut owner_budget()).unwrap();
        drop(owner);
        let mut reopened = h.open().unwrap();
        assert!(reopened
            .observe_current_intent(operation, 112, &mut owner_budget())
            .is_err());
    }
}

#[test]
fn native_owner_v3_authenticated_response_still_must_bind_fresh_challenge() {
    for fault in [Fault::WrongChallenge, Fault::WrongSignature] {
        let h = Harness::new();
        let owner = h.create();
        drop(owner);
        h.service.state.borrow_mut().fault = fault;
        assert!(h.open().is_err());
    }
}

#[test]
fn native_owner_v3_writer_signature_is_verified_before_transport() {
    let h = Harness::new();
    let error = RootOwnerV3::create(
        &h.path(),
        h.enrollment.clone(),
        Writer { malformed: true },
        h.service.clone(),
        &mut owner_budget(),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("V3 root signature rejected"));
    assert_eq!(h.service.state.borrow().calls, 0);
}

#[test]
fn native_owner_v3_callback_cannot_replace_original_owner_budget() {
    struct ReplacingWriter;
    impl RootWriterSignerV3 for ReplacingWriter {
        fn sign(
            &mut self,
            message: &[u8],
            original: &mut OwnerBudgetV3,
        ) -> RootOwnerResultV3<Vec<RootSignatureV3>> {
            let signatures = fixtures().writer.quorum(message);
            *original = owner_budget();
            Ok(signatures)
        }
    }
    let h = Harness::new();
    let error = RootOwnerV3::create(
        &h.path(),
        h.enrollment.clone(),
        ReplacingWriter,
        h.service.clone(),
        &mut owner_budget(),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("CALLBACK_REPLACED_BUDGET"));
    assert_eq!(h.service.state.borrow().calls, 0);
    let h = Harness::new();
    let mut owner = h.create();
    h.service.state.borrow_mut().fault = Fault::ReplaceBudgetAfterCas;
    let error = owner
        .apply(&normal(&state(), 14), 110, &mut owner_budget())
        .err()
        .unwrap();
    assert!(error.to_string().contains("CALLBACK_REPLACED_BUDGET"));
    assert_eq!(h.pending(), 1);
    assert_eq!(h.service.state.borrow().head.version, 1);
    drop(owner);
    h.service.state.borrow_mut().fault = Fault::None;
    h.open()
        .unwrap()
        .resume_pending(&mut owner_budget())
        .unwrap();
}

#[test]
fn native_owner_v3_same_budget_exhaustion_retains_pending_before_cas() {
    let h = Harness::new();
    let mut owner = h.create();
    let until = Instant::now() + Duration::from_secs(120);
    let mut limited = OwnerBudgetV3::new(
        VerificationBudgetV3::with_deadline(16, until).unwrap(),
        until,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    assert!(owner
        .apply(&normal(&state(), 12), 110, &mut limited)
        .is_err());
    assert!(limited.attempts() > 16);
    assert_eq!(h.pending(), 1);
    assert_eq!(h.service.state.borrow().cas_calls, 0);
}

#[test]
fn native_owner_v3_cancellation_after_external_commit_requires_reconciliation() {
    let observed_signal = Arc::new(AtomicBool::new(false));
    let until = Instant::now() + Duration::from_secs(120);
    let observed_budget = OwnerBudgetV3::new(
        VerificationBudgetV3::with_deadline(4096, until).unwrap(),
        until,
        observed_signal.clone(),
    )
    .unwrap();
    observed_signal.store(true, Ordering::Release);
    assert!(observed_budget.check().is_err());
    observed_signal.store(false, Ordering::Release);
    assert!(
        observed_budget.check().is_err(),
        "observed cancellation cannot be cleared through the retained external signal"
    );

    let h = Harness::new();
    let mut owner = h.create();
    let external = Arc::new(AtomicBool::new(false));
    let until = Instant::now() + Duration::from_secs(120);
    let mut original = OwnerBudgetV3::new(
        VerificationBudgetV3::with_deadline(4096, until).unwrap(),
        until,
        external.clone(),
    )
    .unwrap();
    {
        let mut service = h.service.state.borrow_mut();
        service.fault = Fault::CancelAfterCas;
        service.reset_cancellation = Some(external.clone());
    }
    assert!(owner
        .apply(&normal(&state(), 13), 110, &mut original)
        .is_err());
    assert!(
        !external.load(Ordering::Acquire),
        "fixture cleared only its retained external alias"
    );
    assert!(
        original.check().is_err(),
        "explicit cancellation remains latched after the callback clears its alias"
    );
    assert_eq!(h.pending(), 1);
    assert_eq!(h.service.state.borrow().head.version, 1);
    drop(owner);
    h.service.state.borrow_mut().fault = Fault::None;
    let mut reopened = h.open().unwrap();
    reopened.resume_pending(&mut owner_budget()).unwrap();
    assert_eq!(h.pending(), 0);
}

#[test]
fn native_owner_v3_storage_tamper_schema_alias_and_concurrent_open_fail_closed() {
    let h = Harness::new();
    let owner = h.create();
    assert!(h.open().is_err(), "concurrent exclusive owner refused");
    drop(owner);
    let foreign = rusqlite::Connection::open(h.path()).unwrap();
    foreign
        .execute_batch("CREATE TRIGGER untrusted AFTER UPDATE ON current BEGIN SELECT 1; END")
        .unwrap();
    drop(foreign);
    let calls = h.service.state.borrow().calls;
    assert!(h.open().is_err());
    assert_eq!(h.service.state.borrow().calls, calls);
    let alias = h.directory.path().join("alias.sqlite");
    symlink(h.path(), &alias).unwrap();
    assert!(RootOwnerV3::open_existing(
        &alias,
        h.enrollment.clone(),
        Writer { malformed: false },
        h.service.clone(),
        &mut owner_budget()
    )
    .is_err());
    fs::set_permissions(h.path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(h.open().is_err());
}

#[test]
fn native_owner_v3_changed_current_bytes_and_replaced_database_are_not_authority() {
    let h = Harness::new();
    let mut owner = h.create();
    let foreign = rusqlite::Connection::open(h.path()).unwrap();
    foreign
        .execute("UPDATE current SET state=zeroblob(length(state))", [])
        .unwrap();
    drop(foreign);
    let calls = h.service.state.borrow().calls;
    assert!(owner.context(&mut owner_budget()).is_err());
    assert_eq!(h.service.state.borrow().calls, calls);
    drop(owner);
    let h = Harness::new();
    let mut owner = h.create();
    let replacement = h.directory.path().join("replacement.sqlite");
    fs::copy(h.path(), &replacement).unwrap();
    fs::rename(&replacement, h.path()).unwrap();
    assert!(owner.context(&mut owner_budget()).is_err());
}

#[test]
fn native_owner_v3_foreign_sqlite_namespace_is_refused_without_mutating_it() {
    let h = Harness::new();
    let legacy = rusqlite::Connection::open(h.path()).unwrap();
    legacy.execute_batch("PRAGMA journal_mode=WAL; PRAGMA user_version=1; CREATE TABLE legacy(value TEXT); INSERT INTO legacy VALUES('retained');").unwrap();
    drop(legacy);
    fs::set_permissions(h.path(), fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::read(h.path()).unwrap();
    let error = h.open().err().unwrap();
    assert!(error.to_string().contains("DATABASE_NAMESPACE"));
    assert_eq!(fs::read(h.path()).unwrap(), before);
    assert_eq!(h.service.state.borrow().calls, 0);
}

#[test]
fn native_owner_v3_reopen_reverifies_retained_signature_bytes() {
    let h = Harness::new();
    let mut owner = h.create();
    owner
        .apply(&normal(&state(), 15), 110, &mut owner_budget())
        .unwrap();
    drop(owner);
    let foreign = rusqlite::Connection::open(h.path()).unwrap();
    let mut wire: Vec<u8> = foreign
        .query_row("SELECT envelope FROM events WHERE version=1", [], |row| {
            row.get(0)
        })
        .unwrap();
    let last = wire.last_mut().unwrap();
    *last ^= 1;
    foreign
        .execute("UPDATE events SET envelope=? WHERE version=1", [wire])
        .unwrap();
    drop(foreign);
    let calls = h.service.state.borrow().calls;
    assert!(h.open().is_err());
    assert_eq!(h.service.state.borrow().calls, calls);
}
