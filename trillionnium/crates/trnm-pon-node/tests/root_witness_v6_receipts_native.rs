//! Real single-SQLite receipt retention through the original V5 Root owner.
//! Finite component controls, not independent custody or WAN evidence.
#![cfg(all(target_os = "linux", feature = "pq-root-v3"))]
#[path = "support/root_recovery_v3_fixture.rs"]
mod fixture;
use fixture::*;
use sha2::{Digest, Sha512};
use std::cell::{Cell, RefCell};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::OnceLock;
use tempfile::TempDir;
use trnm_crypto_primitives::pq_root_v3::RootSignatureV3;
use trnm_pon_node::root_recovery_v3::witnessed_v5::durable::{
    DurableRootWitnessV5, ReceiptedRootWitnessV6, WitnessReceiptCheckpointV6,
};
use trnm_pon_node::root_recovery_v3::witnessed_v5::*;
use trnm_pon_node::root_recovery_v3::*;

fn witness_keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(Keys::generate)
}
struct ReceiptSigner {
    path: PathBuf,
    calls: Rc<Cell<usize>>,
    hold_reader: Rc<Cell<bool>>,
    reader: Rc<RefCell<Option<rusqlite::Connection>>>,
}
impl RootWriterSignerV3 for ReceiptSigner {
    fn sign(
        &mut self,
        message: &[u8],
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Vec<RootSignatureV3>> {
        budget.check()?;
        self.calls.set(self.calls.get() + 1);
        let signed = witness_keys().quorum(message);
        if self.hold_reader.get() {
            let reader = rusqlite::Connection::open(&self.path).unwrap();
            reader
                .execute_batch("BEGIN; SELECT version FROM root_witness_v5;")
                .unwrap();
            *self.reader.borrow_mut() = Some(reader);
        }
        Ok(signed)
    }
}
struct ReceiptHarness {
    directory: TempDir,
    enrollment: JournalEnrollmentV3,
    policy: WitnessPolicyV5,
    calls: Rc<Cell<usize>>,
    hold_reader: Rc<Cell<bool>>,
    reader: Rc<RefCell<Option<rusqlite::Connection>>>,
}
impl ReceiptHarness {
    fn new() -> Self {
        Self::for_enrollment(
            JournalEnrollmentV3::new(
                domain(),
                fixtures().root.policy(),
                100,
                fixtures().writer.roster.clone(),
                fixtures().anchor.roster.clone(),
            )
            .unwrap(),
        )
    }
    fn for_enrollment(enrollment: JournalEnrollmentV3) -> Self {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            directory,
            policy: WitnessPolicyV5::new(&enrollment, [93; 64], 1, witness_keys().roster.clone())
                .unwrap(),
            enrollment,
            calls: Rc::new(Cell::new(0)),
            hold_reader: Rc::new(Cell::new(false)),
            reader: Rc::new(RefCell::new(None)),
        }
    }
    fn path(&self) -> PathBuf {
        self.directory.path().join("receipts.sqlite")
    }
    fn signer(&self) -> ReceiptSigner {
        ReceiptSigner {
            path: self.path(),
            calls: self.calls.clone(),
            hold_reader: self.hold_reader.clone(),
            reader: self.reader.clone(),
        }
    }
    fn create(&self) -> ReceiptedRootWitnessV6 {
        ReceiptedRootWitnessV6::register_new(
            &self.path(),
            self.policy.clone(),
            &self.enrollment,
            self.signer(),
            &mut owner_budget(),
        )
        .unwrap()
    }
    fn open(
        &self,
        checkpoint: WitnessReceiptCheckpointV6,
    ) -> RootOwnerResultV3<ReceiptedRootWitnessV6> {
        ReceiptedRootWitnessV6::open_existing(
            &self.path(),
            self.policy.clone(),
            checkpoint,
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
    fn current(&self, nonce: u8) -> WitnessEnvelopeV5 {
        self.request(None, None, nonce)
    }
    fn initial(&self) -> JournalHeadV3 {
        self.enrollment.initial_head().unwrap()
    }
}
fn next(head: JournalHeadV3) -> JournalHeadV3 {
    JournalHeadV3 {
        version: head.version + 1,
        root: [81; 64],
    }
}
fn disk_state(h: &ReceiptHarness) -> (JournalHeadV3, u64) {
    let db = rusqlite::Connection::open(h.path()).unwrap();
    let (version, root, count): (u64, Vec<u8>, u64) = db.query_row(
        "SELECT version,root,(SELECT COUNT(*) FROM root_witness_receipts_v6) FROM root_witness_v5",
        [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    (
        JournalHeadV3 {
            version,
            root: root.try_into().unwrap(),
        },
        count,
    )
}
#[test]
fn native_receipts_v6_cold_readback_preserves_exact_signatures_without_new_authority() {
    let h = ReceiptHarness::new();
    let mut owner = h.create();
    let request = h.current(1);
    let original_request = request.request.clone();
    let original_writer = request.writer_approvals.clone();
    let response = owner.exchange(request, &mut owner_budget()).unwrap();
    let checkpoint = owner.checkpoint(&mut owner_budget()).unwrap();
    assert_eq!(checkpoint.records, 1);
    let calls = h.calls.get();
    drop(owner);
    let mut recovered = h.open(checkpoint).unwrap();
    let saved = recovered.retained_receipt(1, &mut owner_budget()).unwrap();
    assert_eq!(saved.sequence(), 1);
    assert_eq!(saved.record_digest(), checkpoint.record_digest);
    assert_eq!(saved.request(), &original_request);
    assert_eq!(saved.writer_approvals(), original_writer);
    assert_eq!(saved.receipt(), &response.receipt);
    assert_eq!(saved.witness_approvals(), response.approvals);
    assert_eq!(h.calls.get(), calls, "historical read invokes no signer");
    assert_eq!(
        recovered.checkpoint(&mut owner_budget()).unwrap(),
        checkpoint
    );
    let target = next(h.initial());
    let response = recovered
        .exchange(
            h.request(Some(h.initial()), Some(target), 2),
            &mut owner_budget(),
        )
        .unwrap();
    assert_eq!(response.receipt.outcome, WitnessOutcomeV5::Advanced);
    let checkpoint = recovered.checkpoint(&mut owner_budget()).unwrap();
    drop(recovered);
    let mut recovered = h.open(checkpoint).unwrap();
    let original = recovered.retained_receipt(2, &mut owner_budget()).unwrap();
    assert_eq!(original.receipt().outcome, WitnessOutcomeV5::Advanced);
    let retry = recovered
        .exchange(
            h.request(Some(h.initial()), Some(target), 3),
            &mut owner_budget(),
        )
        .unwrap();
    assert_eq!(
        retry.receipt.outcome,
        WitnessOutcomeV5::Mismatch,
        "historical ACK cannot recreate the live retry privilege"
    );
}
struct LoseAck {
    owner: ReceiptedRootWitnessV6,
    lose: bool,
    checkpoint: Rc<RefCell<Option<WitnessReceiptCheckpointV6>>>,
    cas_calls: Rc<Cell<usize>>,
    advanced_sequence: Rc<Cell<u64>>,
}
impl RootWitnessTransportV5 for LoseAck {
    fn exchange(
        &mut self,
        request: WitnessEnvelopeV5,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedWitnessReceiptV5> {
        if request.request.target.is_some() {
            self.cas_calls.set(self.cas_calls.get() + 1);
        }
        let response = self.owner.exchange(request, budget)?;
        let checkpoint = self.owner.checkpoint(budget)?;
        *self.checkpoint.borrow_mut() = Some(checkpoint);
        if response.receipt.outcome == WitnessOutcomeV5::Advanced {
            self.advanced_sequence.set(checkpoint.records);
            if self.lose {
                self.lose = false;
                return Err(rejected("fixture lost retained ACK"));
            }
        }
        Ok(response)
    }
}
#[test]
fn native_receipts_v6_original_root_owner_recovers_lost_ack_without_repeating_cas() {
    let root = Harness::new();
    let h = ReceiptHarness::for_enrollment(root.enrollment.clone());
    let checkpoint = Rc::new(RefCell::new(None));
    let cas_calls = Rc::new(Cell::new(0));
    let advanced_sequence = Rc::new(Cell::new(0));
    let transport = LoseAck {
        owner: h.create(),
        lose: true,
        checkpoint: checkpoint.clone(),
        cas_calls: cas_calls.clone(),
        advanced_sequence: advanced_sequence.clone(),
    };
    let witness = RootWitnessV5::new(h.policy.clone(), Writer { malformed: false }, transport);
    let mut owner = WitnessedRootOwnerV5::create(
        &root.path(),
        root.enrollment.clone(),
        Writer { malformed: false },
        root.service.clone(),
        witness,
        &mut owner_budget(),
    )
    .unwrap();
    assert!(owner
        .apply(&normal(&state(), 78), 110, &mut owner_budget())
        .is_err());
    assert_eq!(root.pending(), 1);
    assert_eq!(cas_calls.get(), 1);
    // This exact pin survives outside both SQLite files in this control.
    // The in-process fixture does not establish physical fault-domain separation.
    let expected = checkpoint.borrow().unwrap();
    drop(owner);
    let mut recovered = h.open(expected).unwrap();
    let saved = recovered
        .retained_receipt(advanced_sequence.get(), &mut owner_budget())
        .unwrap();
    assert_eq!(saved.receipt().head, expected.head);
    assert_eq!(saved.receipt().outcome, WitnessOutcomeV5::Advanced);
    assert_eq!(recovered.checkpoint(&mut owner_budget()).unwrap(), expected);
    let transport = LoseAck {
        owner: recovered,
        lose: false,
        checkpoint,
        cas_calls: cas_calls.clone(),
        advanced_sequence,
    };
    let witness = RootWitnessV5::new(h.policy.clone(), Writer { malformed: false }, transport);
    let mut recovered_root = WitnessedRootOwnerV5::open_existing(
        &root.path(),
        root.enrollment.clone(),
        Writer { malformed: false },
        root.service.clone(),
        witness,
        &mut owner_budget(),
    )
    .unwrap();
    assert_eq!(
        recovered_root.resume_pending(&mut owner_budget()).unwrap(),
        expected.head
    );
    assert_eq!(root.pending(), 0);
    assert_eq!(cas_calls.get(), 1);
}

#[test]
fn native_receipts_v6_retention_commit_busy_preserves_advanced_head_without_claiming_ack() {
    let h = ReceiptHarness::new();
    let mut owner = h.create();
    let old = owner.checkpoint(&mut owner_budget()).unwrap();
    let target = next(old.head);
    h.hold_reader.set(true);
    let error = owner
        .exchange(
            h.request(Some(old.head), Some(target), 4),
            &mut owner_budget(),
        )
        .err()
        .unwrap();
    assert!(error.to_string().contains("database is locked"), "{error}");
    assert_eq!(h.calls.get(), 1, "signature follows original head COMMIT");
    h.reader.borrow_mut().take();
    h.hold_reader.set(false);
    assert_eq!(disk_state(&h), (target, 0), "no signed ACK retained");
    assert!(owner.exchange(h.current(5), &mut owner_budget()).is_err());
    assert!(owner.checkpoint(&mut owner_budget()).is_err());
    drop(owner);
    assert!(h.open(old).is_err());
    // The fixture supplies an exact target pin. Production must obtain this
    // independently; an uncertain result cannot promote its old pin.
    let exact = WitnessReceiptCheckpointV6 {
        head: target,
        ..old
    };
    let mut recovered = h.open(exact).unwrap();
    assert!(recovered.retained_receipt(1, &mut owner_budget()).is_err());
    drop(recovered);
    let mut recovered = h.open(exact).unwrap();
    let current = recovered
        .exchange(h.current(6), &mut owner_budget())
        .unwrap();
    assert_eq!(current.receipt.outcome, WitnessOutcomeV5::Current);
    assert_eq!(
        recovered.checkpoint(&mut owner_budget()).unwrap().records,
        1
    );
}
#[test]
fn native_receipts_v6_same_head_history_loss_and_signature_tamper_are_rejected() {
    let h = ReceiptHarness::new();
    let mut owner = h.create();
    owner.exchange(h.current(7), &mut owner_budget()).unwrap();
    let old = owner.checkpoint(&mut owner_budget()).unwrap();
    owner.exchange(h.current(8), &mut owner_budget()).unwrap();
    let latest = owner.checkpoint(&mut owner_budget()).unwrap();
    drop(owner);
    let backup = fs::read(h.path()).unwrap();
    let db = rusqlite::Connection::open(h.path()).unwrap();
    db.execute("DELETE FROM root_witness_receipts_v6 WHERE sequence=2", [])
        .unwrap();
    drop(db);
    assert_eq!(disk_state(&h).0, latest.head);
    assert!(
        h.open(latest).is_err(),
        "same Root head does not conceal archive loss"
    );
    // Restoring the independent pin too remains an explicit counterexample.
    drop(h.open(old).unwrap());
    fs::write(h.path(), &backup).unwrap();
    let db = rusqlite::Connection::open(h.path()).unwrap();
    let mut record: Vec<u8> = db
        .query_row(
            "SELECT record FROM root_witness_receipts_v6 WHERE sequence=2",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let last = record.len() - 1;
    record[last] ^= 1;
    let mut hash = Sha512::new();
    hash.update(b"TRNM/RootWitness/ReceiptArchiveRecord/v6\0");
    hash.update((record.len() as u64).to_be_bytes());
    hash.update(&record);
    let changed_digest: [u8; 64] = hash.finalize().into();
    db.execute(
        "UPDATE root_witness_receipts_v6 SET record=?1,digest=?2 WHERE sequence=2",
        rusqlite::params![record, changed_digest.as_slice()],
    )
    .unwrap();
    drop(db);
    let tampered_pin = WitnessReceiptCheckpointV6 {
        record_digest: changed_digest,
        ..latest
    };
    assert!(
        h.open(tampered_pin).is_err(),
        "self-consistent hashes cannot replace original signatures"
    );
}
#[test]
fn native_receipts_v6_fresh_namespace_never_auto_migrates_v5_or_downgrades() {
    let h = ReceiptHarness::new();
    let mut owner = h.create();
    let expected = owner.checkpoint(&mut owner_budget()).unwrap();
    drop(owner);
    assert!(DurableRootWitnessV5::open_existing(
        &h.path(),
        h.policy.clone(),
        h.initial(),
        h.signer(),
        &mut owner_budget()
    )
    .is_err());
    let other = ReceiptHarness::for_enrollment(h.enrollment.clone());
    drop(
        DurableRootWitnessV5::register_new(
            &other.path(),
            other.policy.clone(),
            &other.enrollment,
            other.signer(),
            &mut owner_budget(),
        )
        .unwrap(),
    );
    let before = fs::read(other.path()).unwrap();
    assert!(other.open(expected).is_err());
    assert!(ReceiptedRootWitnessV6::register_new(
        &other.path(),
        other.policy.clone(),
        &other.enrollment,
        other.signer(),
        &mut owner_budget()
    )
    .is_err());
    assert_eq!(fs::read(other.path()).unwrap(), before);
}
#[test]
fn native_receipts_v6_oversized_record_and_live_history_removal_fail_closed() {
    let h = ReceiptHarness::new();
    let mut owner = h.create();
    owner.exchange(h.current(9), &mut owner_budget()).unwrap();
    let expected = owner.checkpoint(&mut owner_budget()).unwrap();
    let db = rusqlite::Connection::open(h.path()).unwrap();
    let record: Vec<u8> = db
        .query_row("SELECT record FROM root_witness_receipts_v6", [], |r| {
            r.get(0)
        })
        .unwrap();
    db.execute("DELETE FROM root_witness_receipts_v6", [])
        .unwrap();
    assert!(owner.exchange(h.current(10), &mut owner_budget()).is_err());
    db.execute(
        "INSERT INTO root_witness_receipts_v6 VALUES(1,?1,?2)",
        rusqlite::params![record, expected.record_digest.as_slice()],
    )
    .unwrap();
    assert!(
        owner.exchange(h.current(11), &mut owner_budget()).is_err(),
        "repair cannot unfence live owner"
    );
    drop(owner);
    db.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE root_witness_receipts_v6 SET record=zeroblob(196609);").unwrap();
    drop(db);
    assert!(h.open(expected).is_err());
}
#[test]
fn native_receipts_v6_replayed_writer_request_cannot_consume_capacity_or_fence_owner() {
    let h = ReceiptHarness::new();
    let mut owner = h.create();
    let original = h.current(12);
    let request = original.request.clone();
    let approvals = original.writer_approvals.clone();
    owner.exchange(original, &mut owner_budget()).unwrap();
    let before = owner.checkpoint(&mut owner_budget()).unwrap();
    let calls = h.calls.get();
    for _ in 0..3 {
        let error = owner
            .exchange(
                WitnessEnvelopeV5 {
                    request: request.clone(),
                    writer_approvals: approvals.clone(),
                },
                &mut owner_budget(),
            )
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            "ROOT_WITNESS_V6_REQUEST_ALREADY_RETAINED"
        );
        assert_eq!(owner.checkpoint(&mut owner_budget()).unwrap(), before);
        assert_eq!(h.calls.get(), calls);
    }
    let target = next(h.initial());
    let response = owner
        .exchange(
            h.request(Some(h.initial()), Some(target), 13),
            &mut owner_budget(),
        )
        .unwrap();
    assert_eq!(response.receipt.outcome, WitnessOutcomeV5::Advanced);
    let after = owner.checkpoint(&mut owner_budget()).unwrap();
    assert_eq!(after.records, before.records + 1);
    drop(owner);
    let mut recovered = h.open(after).unwrap();
    let error = recovered
        .exchange(
            WitnessEnvelopeV5 {
                request,
                writer_approvals: approvals,
            },
            &mut owner_budget(),
        )
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "ROOT_WITNESS_V6_REQUEST_ALREADY_RETAINED"
    );
    assert_eq!(recovered.checkpoint(&mut owner_budget()).unwrap(), after);
}
