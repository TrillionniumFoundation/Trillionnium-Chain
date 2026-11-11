//! Real SQLite files and real dual-family signatures for the typed V5 owner.
//! These controls do not establish independent physical custody or a daemon.
#![cfg(all(target_os = "linux", feature = "pq-root-v3"))]

#[path = "support/root_recovery_v3_fixture.rs"]
mod fixture;
use fixture::*;
use std::cell::{Cell, RefCell};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use trnm_crypto_primitives::pq_root_v3::{RootSignatureV3, VerificationBudgetV3};
use trnm_pon_node::root_recovery_v3::witnessed_v5::durable::DurableRootWitnessV5;
use trnm_pon_node::root_recovery_v3::witnessed_v5::*;
use trnm_pon_node::root_recovery_v3::*;

fn witness_keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(Keys::generate)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SignFault {
    None,
    Error,
    WrongQuorum,
    ReplaceBudget,
    ReplaceBudgetError,
    Cancel,
    ChangeRow,
}

struct ReceiptSigner {
    fault: Rc<Cell<SignFault>>,
    calls: Rc<Cell<usize>>,
    path: PathBuf,
}
impl RootWriterSignerV3 for ReceiptSigner {
    fn sign(
        &mut self,
        message: &[u8],
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Vec<RootSignatureV3>> {
        self.calls.set(self.calls.get() + 1);
        budget.check()?;
        if self.fault.get() == SignFault::Error {
            return Err(rejected("fixture signing failed"));
        }
        let approvals = if self.fault.get() == SignFault::WrongQuorum {
            fixtures().writer.quorum(message)
        } else {
            witness_keys().quorum(message)
        };
        match self.fault.get() {
            SignFault::ReplaceBudget | SignFault::ReplaceBudgetError => *budget = owner_budget(),
            SignFault::Cancel => budget.cancel(),
            SignFault::ChangeRow => {
                rusqlite::Connection::open(&self.path)
                    .unwrap()
                    .execute(
                        "UPDATE root_witness_v5 SET root=?1",
                        [[88_u8; 64].as_slice()],
                    )
                    .unwrap();
            }
            _ => {}
        }
        if self.fault.get() == SignFault::ReplaceBudgetError {
            return Err(rejected("fixture replaced budget then returned Err"));
        }
        Ok(approvals)
    }
}

struct DurableHarness {
    directory: TempDir,
    policy: WitnessPolicyV5,
    enrollment: JournalEnrollmentV3,
    initial: JournalHeadV3,
    fault: Rc<Cell<SignFault>>,
    calls: Rc<Cell<usize>>,
}
impl DurableHarness {
    fn new() -> Self {
        let enrollment = JournalEnrollmentV3::new(
            domain(),
            fixtures().root.policy(),
            100,
            fixtures().writer.roster.clone(),
            fixtures().anchor.roster.clone(),
        )
        .unwrap();
        Self::for_enrollment(&enrollment)
    }
    fn for_enrollment(enrollment: &JournalEnrollmentV3) -> Self {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            directory,
            policy: WitnessPolicyV5::new(enrollment, [91; 64], 1, witness_keys().roster.clone())
                .unwrap(),
            enrollment: enrollment.clone(),
            initial: enrollment.initial_head().unwrap(),
            fault: Rc::new(Cell::new(SignFault::None)),
            calls: Rc::new(Cell::new(0)),
        }
    }
    fn path(&self) -> PathBuf {
        self.directory.path().join("witness.sqlite")
    }
    fn signer(&self) -> ReceiptSigner {
        ReceiptSigner {
            fault: self.fault.clone(),
            calls: self.calls.clone(),
            path: self.path(),
        }
    }
    fn create(&self) -> DurableRootWitnessV5 {
        DurableRootWitnessV5::register_new(
            &self.path(),
            self.policy.clone(),
            &self.enrollment,
            self.signer(),
            &mut owner_budget(),
        )
        .unwrap()
    }
    fn open(&self, head: JournalHeadV3) -> RootOwnerResultV3<DurableRootWitnessV5> {
        DurableRootWitnessV5::open_existing(
            &self.path(),
            self.policy.clone(),
            head,
            self.signer(),
            &mut owner_budget(),
        )
    }
    fn request(
        &self,
        expected: Option<JournalHeadV3>,
        target: Option<JournalHeadV3>,
        nonce: u8,
    ) -> WitnessEnvelopeV5 {
        let request = WitnessRequestV5 {
            binding: self.policy.binding(),
            challenge: [nonce; 32],
            expected,
            target,
        };
        let writer_approvals = fixtures().writer.quorum(&request.message().unwrap());
        WitnessEnvelopeV5 {
            request,
            writer_approvals,
        }
    }
    fn current(&self) -> WitnessEnvelopeV5 {
        self.request(None, None, 1)
    }
    fn cas(&self, previous: JournalHeadV3, next: JournalHeadV3) -> WitnessEnvelopeV5 {
        self.request(Some(previous), Some(next), 2)
    }
    fn assert_fenced(&self, owner: &mut DurableRootWitnessV5) {
        let error = owner
            .exchange(self.current(), &mut owner_budget())
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "ROOT_WITNESS_V5_DURABLE_FENCED");
    }
}
fn next(previous: JournalHeadV3, byte: u8) -> JournalHeadV3 {
    JournalHeadV3 {
        version: previous.version + 1,
        root: [byte; 64],
    }
}
fn verify(
    reply: &SignedWitnessReceiptV5,
    request: &WitnessRequestV5,
    head: JournalHeadV3,
    outcome: WitnessOutcomeV5,
) {
    assert_eq!(reply.receipt.binding, request.binding);
    assert_eq!(reply.receipt.challenge, request.challenge);
    assert_eq!(reply.receipt.request_digest, request.digest().unwrap());
    assert_eq!(reply.receipt.head, head);
    assert_eq!(reply.receipt.outcome, outcome);
    witness_keys()
        .roster
        .verify_quorum(
            &reply.receipt.message().unwrap(),
            &reply.approvals,
            &mut VerificationBudgetV3::with_deadline(16, Instant::now() + Duration::from_secs(120))
                .unwrap(),
        )
        .unwrap();
}
fn exchange(
    owner: &mut DurableRootWitnessV5,
    envelope: WitnessEnvelopeV5,
    head: JournalHeadV3,
    outcome: WitnessOutcomeV5,
) {
    let request = envelope.request.clone();
    let reply = owner.exchange(envelope, &mut owner_budget()).unwrap();
    verify(&reply, &request, head, outcome);
}
fn disk_head(path: &Path) -> JournalHeadV3 {
    let database = rusqlite::Connection::open(path).unwrap();
    let (version, root): (u64, Vec<u8>) = database
        .query_row("SELECT version,root FROM root_witness_v5", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    JournalHeadV3 {
        version,
        root: root.try_into().unwrap(),
    }
}

#[test]
fn native_durable_witness_v5_exact_cas_retry_and_cold_reopen_have_dual_family_receipts() {
    let h = DurableHarness::new();
    let mut owner = h.create();
    exchange(
        &mut owner,
        h.current(),
        h.initial,
        WitnessOutcomeV5::Current,
    );
    let target = next(h.initial, 51);
    exchange(
        &mut owner,
        h.cas(h.initial, target),
        target,
        WitnessOutcomeV5::Advanced,
    );
    assert_eq!(disk_head(&h.path()), target);
    exchange(
        &mut owner,
        h.cas(h.initial, target),
        target,
        WitnessOutcomeV5::Advanced,
    );
    drop(owner);
    assert!(h.open(h.initial).is_err());
    let mut owner = h.open(target).unwrap();
    exchange(&mut owner, h.current(), target, WitnessOutcomeV5::Current);
    // The predecessor persisted through cold open; no in-memory retry cache.
    exchange(
        &mut owner,
        h.cas(h.initial, target),
        target,
        WitnessOutcomeV5::Advanced,
    );
}

#[test]
fn native_durable_witness_v5_stale_database_requires_surviving_independent_reopen_pin() {
    let h = DurableHarness::new();
    drop(h.create());
    let backup = h.directory.path().join("old.sqlite");
    fs::copy(h.path(), &backup).unwrap();
    let mut owner = h.open(h.initial).unwrap();
    let target = next(h.initial, 52);
    exchange(
        &mut owner,
        h.cas(h.initial, target),
        target,
        WitnessOutcomeV5::Advanced,
    );
    drop(owner);
    fs::copy(&backup, h.path()).unwrap();
    let error = h.open(target).err().unwrap();
    assert_eq!(error.to_string(), "ROOT_WITNESS_V5_INDEPENDENT_REOPEN_HEAD");
    // Explicit impossibility contrast: restoring the independent pin as well
    // admits the old state. Durable SQLite alone is not independent freshness.
    let mut old = h.open(h.initial).unwrap();
    exchange(&mut old, h.current(), h.initial, WitnessOutcomeV5::Current);
}

#[test]
fn native_durable_witness_v5_wrong_predecessor_and_competing_successor_are_mismatches() {
    let h = DurableHarness::new();
    let mut owner = h.create();
    let target = next(h.initial, 53);
    exchange(
        &mut owner,
        h.cas(h.initial, target),
        target,
        WitnessOutcomeV5::Advanced,
    );
    let wrong_previous = JournalHeadV3 {
        version: h.initial.version,
        root: [66; 64],
    };
    exchange(
        &mut owner,
        h.cas(wrong_previous, target),
        target,
        WitnessOutcomeV5::Mismatch,
    );
    exchange(
        &mut owner,
        h.cas(h.initial, next(h.initial, 54)),
        target,
        WitnessOutcomeV5::Mismatch,
    );
    assert_eq!(disk_head(&h.path()), target);
    drop(owner);
    let mut owner = h.open(target).unwrap();
    exchange(
        &mut owner,
        h.cas(wrong_previous, target),
        target,
        WitnessOutcomeV5::Mismatch,
    );
}

#[test]
fn native_durable_witness_v5_real_sqlite_commit_busy_fences_until_explicit_reopen() {
    let h = DurableHarness::new();
    let mut owner = h.create();
    // A real SHARED reader permits BEGIN IMMEDIATE and UPDATE but prevents the
    // writer's DELETE-journal COMMIT from obtaining its exclusive lock.
    let reader = rusqlite::Connection::open(h.path()).unwrap();
    reader
        .execute_batch("BEGIN; SELECT version FROM root_witness_v5;")
        .unwrap();
    let target = next(h.initial, 55);
    let error = owner
        .exchange(h.cas(h.initial, target), &mut owner_budget())
        .err()
        .unwrap();
    assert!(error.to_string().contains("database is locked"), "{error}");
    assert_eq!(h.calls.get(), 0, "no signer before a successful COMMIT");
    reader.execute_batch("ROLLBACK").unwrap();
    drop(reader);
    h.assert_fenced(&mut owner);
    drop(owner);
    assert_eq!(disk_head(&h.path()), h.initial);
    assert!(h.open(target).is_err());
    let mut recovered = h.open(h.initial).unwrap();
    exchange(
        &mut recovered,
        h.cas(h.initial, target),
        target,
        WitnessOutcomeV5::Advanced,
    );
}

#[test]
fn native_durable_witness_v5_signing_failure_and_wrong_quorum_preserve_committed_head() {
    for fault in [SignFault::Error, SignFault::WrongQuorum] {
        let h = DurableHarness::new();
        let mut owner = h.create();
        let target = next(h.initial, 56);
        h.fault.set(fault);
        assert!(owner
            .exchange(h.cas(h.initial, target), &mut owner_budget())
            .is_err());
        assert_eq!(disk_head(&h.path()), target);
        h.fault.set(SignFault::None);
        h.assert_fenced(&mut owner);
        drop(owner);
        assert!(h.open(h.initial).is_err());
        let mut recovered = h.open(target).unwrap();
        exchange(
            &mut recovered,
            h.current(),
            target,
            WitnessOutcomeV5::Current,
        );
    }
}

#[test]
fn native_durable_witness_v5_budget_replacement_on_ok_or_err_and_cancellation_fence() {
    for fault in [
        SignFault::ReplaceBudget,
        SignFault::ReplaceBudgetError,
        SignFault::Cancel,
    ] {
        let h = DurableHarness::new();
        let mut owner = h.create();
        let target = next(h.initial, 57);
        h.fault.set(fault);
        let error = owner
            .exchange(h.cas(h.initial, target), &mut owner_budget())
            .err()
            .unwrap();
        let expected = if fault == SignFault::Cancel {
            "ROOT_OWNER_ORIGINAL_BUDGET_EXPIRED_OR_CANCELLED"
        } else {
            "ROOT_OWNER_CALLBACK_REPLACED_BUDGET"
        };
        assert_eq!(error.to_string(), expected);
        assert_eq!(disk_head(&h.path()), target);
        h.fault.set(SignFault::None);
        h.assert_fenced(&mut owner);
        drop(owner);
        let mut recovered = h.open(target).unwrap();
        exchange(
            &mut recovered,
            h.current(),
            target,
            WitnessOutcomeV5::Current,
        );
    }
}

#[test]
fn native_durable_witness_v5_unauthenticated_requests_cannot_mutate_or_fence() {
    let h = DurableHarness::new();
    let mut owner = h.create();
    let target = next(h.initial, 58);
    for fault in 0..4 {
        let mut envelope = h.cas(h.initial, target);
        match fault {
            0 => envelope.request.binding[0] ^= 1,
            1 => envelope.writer_approvals[0].signature[0] ^= 1,
            2 => envelope.writer_approvals.truncate(2),
            3 => envelope.request.target = None,
            _ => unreachable!(),
        }
        assert!(owner.exchange(envelope, &mut owner_budget()).is_err());
        assert_eq!(disk_head(&h.path()), h.initial);
        assert_eq!(h.calls.get(), 0);
    }
    exchange(
        &mut owner,
        h.current(),
        h.initial,
        WitnessOutcomeV5::Current,
    );
    exchange(
        &mut owner,
        h.cas(h.initial, target),
        target,
        WitnessOutcomeV5::Advanced,
    );
}

#[test]
fn native_durable_witness_v5_complete_policy_and_live_stored_binding_are_enforced() {
    let h = DurableHarness::new();
    drop(h.create());
    let enrollment = JournalEnrollmentV3::new(
        domain(),
        fixtures().root.policy(),
        100,
        fixtures().writer.roster.clone(),
        fixtures().anchor.roster.clone(),
    )
    .unwrap();
    for (restore_domain, epoch) in [([92; 64], 1), ([91; 64], 2)] {
        let other = WitnessPolicyV5::new(
            &enrollment,
            restore_domain,
            epoch,
            witness_keys().roster.clone(),
        )
        .unwrap();
        assert!(DurableRootWitnessV5::open_existing(
            &h.path(),
            other,
            h.initial,
            h.signer(),
            &mut owner_budget()
        )
        .is_err());
    }
    let mut owner = h.open(h.initial).unwrap();
    let external = rusqlite::Connection::open(h.path()).unwrap();
    let policy: Vec<u8> = external
        .query_row("SELECT policy FROM root_witness_v5", [], |row| row.get(0))
        .unwrap();
    external
        .execute(
            "UPDATE root_witness_v5 SET policy=zeroblob(length(policy))",
            [],
        )
        .unwrap();
    let error = owner
        .exchange(h.current(), &mut owner_budget())
        .err()
        .unwrap();
    assert_eq!(error.to_string(), "ROOT_WITNESS_V5_DURABLE_POLICY_OR_ROW");
    external
        .execute("UPDATE root_witness_v5 SET policy=?1", [policy])
        .unwrap();
    h.assert_fenced(&mut owner);
    drop(owner);
    drop(external);
    let mut reopened = h.open(h.initial).unwrap();
    exchange(
        &mut reopened,
        h.current(),
        h.initial,
        WitnessOutcomeV5::Current,
    );
}

#[test]
fn native_durable_witness_v5_exclusive_lock_and_named_inode_are_required() {
    let h = DurableHarness::new();
    let mut owner = h.create();
    let error = h.open(h.initial).err().unwrap();
    assert_eq!(error.to_string(), "ROOT_WITNESS_V5_DURABLE_BUSY");
    let moved = h.directory.path().join("moved.sqlite");
    fs::rename(h.path(), &moved).unwrap();
    fs::copy(&moved, h.path()).unwrap();
    let error = owner
        .exchange(h.current(), &mut owner_budget())
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "ROOT_WITNESS_V5_DURABLE_DATABASE_REPLACED"
    );
    h.assert_fenced(&mut owner);
}

#[test]
fn native_durable_witness_v5_foreign_namespace_and_extra_schema_are_refused() {
    let h = DurableHarness::new();
    let mut cancelled = owner_budget();
    cancelled.cancel();
    assert!(DurableRootWitnessV5::register_new(
        &h.path(),
        h.policy.clone(),
        &h.enrollment,
        h.signer(),
        &mut cancelled,
    )
    .is_err());
    assert!(!h.path().exists());
    let mut other_policy = fixtures().root.policy();
    other_policy.expires_at_unix -= 1;
    let other_enrollment = JournalEnrollmentV3::new(
        domain(),
        other_policy,
        100,
        fixtures().writer.roster.clone(),
        fixtures().anchor.roster.clone(),
    )
    .unwrap();
    let error = DurableRootWitnessV5::register_new(
        &h.path(),
        h.policy.clone(),
        &other_enrollment,
        h.signer(),
        &mut owner_budget(),
    )
    .err()
    .unwrap();
    assert_eq!(error.to_string(), "ROOT_WITNESS_V5_COMPLETE_ENROLLMENT");
    assert!(!h.path().exists());
    for bytes in [b"".as_slice(), b"partial existing registration".as_slice()] {
        fs::write(h.path(), bytes).unwrap();
        fs::set_permissions(h.path(), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(DurableRootWitnessV5::register_new(
            &h.path(),
            h.policy.clone(),
            &h.enrollment,
            h.signer(),
            &mut owner_budget(),
        )
        .is_err());
        assert_eq!(fs::read(h.path()).unwrap(), bytes);
        fs::remove_file(h.path()).unwrap();
    }
    let foreign = rusqlite::Connection::open(h.path()).unwrap();
    foreign
        .execute_batch("CREATE TABLE foreign_data(value INTEGER); PRAGMA user_version=5;")
        .unwrap();
    drop(foreign);
    fs::set_permissions(h.path(), fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::read(h.path()).unwrap();
    let error = h.open(h.initial).err().unwrap();
    assert_eq!(
        error.to_string(),
        "ROOT_WITNESS_V5_DURABLE_DATABASE_NAMESPACE"
    );
    assert_eq!(fs::read(h.path()).unwrap(), before);
    fs::remove_file(h.path()).unwrap();
    drop(h.create());
    let external = rusqlite::Connection::open(h.path()).unwrap();
    external
        .execute_batch("CREATE TABLE extra(value INTEGER)")
        .unwrap();
    drop(external);
    let error = h.open(h.initial).err().unwrap();
    assert_eq!(error.to_string(), "ROOT_WITNESS_V5_DURABLE_SCHEMA");
}

#[test]
fn native_durable_witness_v5_signer_callback_cannot_replace_committed_row_before_ack() {
    for cas in [false, true] {
        let h = DurableHarness::new();
        let mut owner = h.create();
        let target = if cas { next(h.initial, 59) } else { h.initial };
        let envelope = if cas {
            h.cas(h.initial, target)
        } else {
            h.current()
        };
        h.fault.set(SignFault::ChangeRow);
        let error = owner.exchange(envelope, &mut owner_budget()).err().unwrap();
        assert_eq!(error.to_string(), "ROOT_WITNESS_V5_DURABLE_STATE_CHANGED");
        h.fault.set(SignFault::None);
        h.assert_fenced(&mut owner);
        drop(owner);
        assert!(h.open(target).is_err());
    }
}

struct LoseAcknowledgement {
    owner: DurableRootWitnessV5,
    lose: bool,
    cas_calls: Rc<Cell<usize>>,
    retained: Rc<RefCell<Option<SignedWitnessReceiptV5>>>,
}
impl RootWitnessTransportV5 for LoseAcknowledgement {
    fn exchange(
        &mut self,
        envelope: WitnessEnvelopeV5,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedWitnessReceiptV5> {
        let cas = envelope.request.target.is_some();
        if cas {
            self.cas_calls.set(self.cas_calls.get() + 1);
        }
        let receipt = self.owner.exchange(envelope, budget)?;
        if cas && self.lose {
            self.lose = false;
            *self.retained.borrow_mut() = Some(receipt);
            return Err(rejected(
                "fixture dropped durable ACK before client receipt",
            ));
        }
        Ok(receipt)
    }
}

#[test]
fn native_durable_witness_v5_root_lost_ack_cold_recovery_does_not_repeat_cas() {
    let root = Harness::new();
    let h = DurableHarness::for_enrollment(&root.enrollment);
    let calls = Rc::new(Cell::new(0));
    let retained = Rc::new(RefCell::new(None));
    let transport = LoseAcknowledgement {
        owner: h.create(),
        lose: true,
        cas_calls: calls.clone(),
        retained: retained.clone(),
    };
    let client = RootWitnessV5::new(h.policy.clone(), Writer { malformed: false }, transport);
    let mut owner = WitnessedRootOwnerV5::create(
        &root.path(),
        root.enrollment.clone(),
        Writer { malformed: false },
        root.service.clone(),
        client,
        &mut owner_budget(),
    )
    .unwrap();
    let envelope = normal(&state(), 77);
    assert!(owner.apply(&envelope, 110, &mut owner_budget()).is_err());
    assert_eq!(root.pending(), 1);
    assert_eq!(calls.get(), 1);
    // This authenticated receipt is retained outside both restored SQLite files.
    let reply = retained.borrow_mut().take().unwrap();
    witness_keys()
        .roster
        .verify_quorum(
            &reply.receipt.message().unwrap(),
            &reply.approvals,
            &mut VerificationBudgetV3::with_deadline(16, Instant::now() + Duration::from_secs(120))
                .unwrap(),
        )
        .unwrap();
    let expected = reply.receipt.head;
    assert_eq!(reply.receipt.outcome, WitnessOutcomeV5::Advanced);
    assert_eq!(disk_head(&h.path()), expected);
    drop(owner);
    assert!(h.open(h.initial).is_err());
    let transport = LoseAcknowledgement {
        owner: h.open(expected).unwrap(),
        lose: false,
        cas_calls: calls.clone(),
        retained,
    };
    let client = RootWitnessV5::new(h.policy.clone(), Writer { malformed: false }, transport);
    let mut reopened = WitnessedRootOwnerV5::open_existing(
        &root.path(),
        root.enrollment.clone(),
        Writer { malformed: false },
        root.service.clone(),
        client,
        &mut owner_budget(),
    )
    .unwrap();
    let completed = reopened.resume_pending(&mut owner_budget()).unwrap();
    assert_eq!(completed, expected);
    assert_eq!(calls.get(), 1);
    assert_eq!(root.pending(), 0);
    assert_eq!(
        reopened.context(&mut owner_budget()).unwrap().head,
        expected
    );
}
