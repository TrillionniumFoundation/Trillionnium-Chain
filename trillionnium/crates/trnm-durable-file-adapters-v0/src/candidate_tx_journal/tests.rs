use super::*;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trnm_tx_lifecycle_v0::{
    AuthorizationVerifierV0, ProductionTxCoordinatorV0, ResourceLimitsV0, TxIntentV0, TxLifecycleV0,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Point {
    BeforeStage,
    PartialStage,
    BeforeFileSync,
    FileSynced,
    Published,
    DirectorySynced,
    ResponseLost,
}
const POINTS: [Point; 7] = [
    Point::BeforeStage,
    Point::PartialStage,
    Point::BeforeFileSync,
    Point::FileSynced,
    Point::Published,
    Point::DirectorySynced,
    Point::ResponseLost,
];
#[derive(Clone, Copy)]
pub(super) struct Fault {
    point: Point,
    park: bool,
}

#[derive(Clone, Copy)]
pub(super) struct PublicationAttack {
    point: Point,
    replace_inode: bool,
}

impl CandidateTxFileJournalV0 {
    pub(super) fn at_fault(&mut self, point: Point) -> Result<()> {
        if self
            .publication_attack
            .is_some_and(|attack| attack.point == point)
        {
            let attack = self.publication_attack.take().unwrap();
            let name = match point {
                Point::FileSynced => STAGE.to_owned(),
                Point::Published | Point::DirectorySynced => frame_name(self.state.sequence + 1),
                _ => panic!("publication attack must target an existing written file"),
            };
            let mut bytes = self.read_file(&name, MAX_FRAME_BYTES).unwrap();
            if attack.replace_inode {
                // Keep all bytes identical so only retained-descriptor
                // identity binding, not the frame checksum, detects this.
                // Preserve the original's single link at a displaced name,
                // so checking the written fd's nlink alone cannot catch this.
                rfs::renameat_with(
                    &self.directory,
                    &name,
                    &self.directory,
                    "test-displaced-publication",
                    RenameFlags::NOREPLACE,
                )
                .unwrap();
                let mut replacement: File = rfs::openat(
                    &self.directory,
                    &name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .unwrap()
                .into();
                replacement.write_all(&bytes).unwrap();
                replacement.sync_all().unwrap();
            } else {
                // Retain the inode and exact file length. An inode-only
                // publication fence must not accept altered frame bytes.
                bytes[0] ^= 1;
                let mut named: File = rfs::openat(
                    &self.directory,
                    &name,
                    OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .unwrap()
                .into();
                named.write_all(&bytes).unwrap();
                named.sync_all().unwrap();
            }
            self.directory.sync_all().unwrap();
        }
        if !self.fault.is_some_and(|fault| fault.point == point) {
            return Ok(());
        }
        let fault = self.fault.take().unwrap();
        if fault.park {
            let ready =
                std::env::var_os("TRNM_TX_TEST_READY").expect("isolated child ready marker");
            let mut marker = File::create(ready).unwrap();
            marker.write_all(b"fault cut reached").unwrap();
            marker.sync_all().unwrap();
            loop {
                thread::park_timeout(Duration::from_secs(1));
            }
        }
        Err(CandidateTxJournalErrorV0::Io(io::Error::other(
            "injected uncertain write or lost response",
        )))
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "trnm-tx-journal-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[derive(Clone, Copy)]
struct AuthorizedFixture;
impl AuthorizationVerifierV0 for AuthorizedFixture {
    type Error = io::Error;
    fn verify(
        &self,
        _sender: Digest32V0,
        _digest: Digest32V0,
        authorization: &[u8],
    ) -> std::result::Result<(), Self::Error> {
        if authorization == [0x77] {
            Ok(())
        } else {
            Err(io::Error::other("fixture authorization rejected"))
        }
    }
}
fn identity() -> CandidateTxJournalIdentityV0 {
    CandidateTxJournalIdentityV0 {
        chain_id: Digest32V0([1; 32]),
        journal_id: Digest32V0([2; 32]),
    }
}
fn intent(nonce: u64, fee: u128) -> TxIntentV0 {
    TxIntentV0 {
        chain_id: identity().chain_id,
        sender: Digest32V0([3; 32]),
        nonce,
        fee_bid: fee,
        valid_until_height: 100,
        resource_limits: ResourceLimitsV0 {
            max_compute: 100,
            max_state_reads: 2,
            max_state_writes: 2,
            max_event_bytes: 64,
        },
        payload: vec![0x44],
        authorization: vec![0x77],
    }
}
fn admitted(nonce: u64, fee: u128) -> TxRecordV0 {
    let mut core = TxLifecycleV0::new(identity().chain_id, AuthorizedFixture);
    let id = core.admit(intent(nonce, fee), 1).unwrap();
    core.record(id).unwrap().clone()
}
fn open(path: &Path) -> CandidateTxFileJournalV0 {
    // Another parallel test can fork while this test drops its owner; until
    // that child execs, it briefly inherits the old open-file-description lock.
    // Only setup/restart calls retry. The competing-owner assertions below
    // call the actual nonblocking constructor directly and require Locked.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match CandidateTxFileJournalV0::open(
            path,
            identity(),
            CandidateTxJournalLimitsV0::default(),
        ) {
            Ok(owner) => return owner,
            Err(CandidateTxJournalErrorV0::Locked) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("open journal: {error}"),
        }
    }
}
fn baseline(path: &Path) -> (CandidateTxFileJournalV0, TxRecordV0) {
    let mut journal = open(path);
    let mut coordinator = ProductionTxCoordinatorV0::new(identity().chain_id, AuthorizedFixture);
    let tx_id = coordinator
        .admit_and_persist(&mut journal, intent(0, 10), 1)
        .unwrap()
        .tx_id;
    let record = journal
        .load_latest(identity().chain_id)
        .unwrap()
        .into_iter()
        .find(|entry| entry.record.tx_id == tx_id)
        .unwrap()
        .record;
    (journal, record)
}
fn pair(previous: &TxRecordV0) -> (TxRecordV0, TxRecordV0) {
    let admitted = admitted(previous.intent.nonce, previous.intent.fee_bid + 10);
    let mut replaced = previous.clone();
    replaced.phase = TxPhaseV0::Tombstoned;
    replaced.lifecycle_sequence += 1;
    replaced.tombstone = Some(TombstoneReasonV0::Replaced { by: admitted.tx_id });
    (replaced, admitted)
}

#[test]
fn candidate_flags_and_successful_replacement_ack_survive_restart() {
    assert!(!std::hint::black_box(
        CANDIDATE_TX_JOURNAL_PRODUCTION_ACTIVATION_V0
    ));
    assert!(!std::hint::black_box(
        CANDIDATE_TX_JOURNAL_EXTERNAL_ROLLBACK_PROTECTION_V0
    ));
    let directory = Directory::new();
    let (mut journal, old) = baseline(&directory.0);
    let mut coordinator =
        ProductionTxCoordinatorV0::recover(identity().chain_id, AuthorizedFixture, &mut journal)
            .unwrap();
    let acknowledgement = coordinator
        .admit_and_persist(&mut journal, intent(0, 20), 1)
        .unwrap();
    assert_ne!(acknowledgement.tx_id, old.tx_id);
    let before = journal.load_latest(identity().chain_id).unwrap();
    assert_eq!(before.len(), 2);
    assert_eq!(
        before
            .iter()
            .find(|entry| entry.record.tx_id == old.tx_id)
            .unwrap()
            .record
            .tombstone,
        Some(TombstoneReasonV0::Replaced {
            by: acknowledgement.tx_id
        })
    );
    drop(journal);
    let mut journal = open(&directory.0);
    assert_eq!(journal.load_latest(identity().chain_id).unwrap(), before);
    let mut recovered =
        ProductionTxCoordinatorV0::recover(identity().chain_id, AuthorizedFixture, &mut journal)
            .unwrap();
    assert_eq!(
        recovered
            .admit_and_persist(&mut journal, intent(0, 20), 1)
            .unwrap(),
        acknowledgement
    );
}

#[test]
fn real_file_replacement_error_matrix_is_atomic_and_requires_recovery() {
    for point in POINTS {
        let directory = Directory::new();
        let (mut journal, previous) = baseline(&directory.0);
        let (replaced, admitted) = pair(&previous);
        let old_digest = previous.canonical_record_digest_v0();
        journal.fault = Some(Fault { point, park: false });
        assert!(
            journal
                .compare_and_replace(old_digest, &replaced, &admitted)
                .is_err(),
            "{point:?}"
        );
        assert!(journal.is_poisoned(), "{point:?}");
        assert!(matches!(
            journal.load_latest(identity().chain_id),
            Err(CandidateTxJournalErrorV0::Poisoned)
        ));
        drop(journal);
        assert_atomic_recovery(&directory.0, &previous, &replaced, &admitted, point);
    }
}
fn assert_atomic_recovery(
    path: &Path,
    previous: &TxRecordV0,
    replaced: &TxRecordV0,
    admitted: &TxRecordV0,
    point: Point,
) {
    let mut journal = open(path);
    let records = journal.load_latest(identity().chain_id).unwrap();
    let was_published = matches!(
        point,
        Point::Published | Point::DirectorySynced | Point::ResponseLost
    );
    if was_published {
        assert_eq!(records.len(), 2, "{point:?}");
        let old = records
            .iter()
            .find(|record| record.record.tx_id == replaced.tx_id)
            .unwrap();
        let new = records
            .iter()
            .find(|record| record.record.tx_id == admitted.tx_id)
            .unwrap();
        assert_eq!(&old.record, replaced);
        assert_eq!(&new.record, admitted);
        assert_eq!(old.durable.journal_sequence, new.durable.journal_sequence);
    } else {
        assert_eq!(records.len(), 1, "{point:?}");
        assert_eq!(&records[0].record, previous);
    }
    let receipt = journal
        .compare_and_replace(previous.canonical_record_digest_v0(), replaced, admitted)
        .unwrap();
    assert_eq!(
        receipt.replaced.journal_sequence,
        receipt.admitted.journal_sequence
    );
    assert_eq!(
        journal
            .compare_and_replace(previous.canonical_record_digest_v0(), replaced, admitted)
            .unwrap(),
        receipt
    );
    let mut coordinator =
        ProductionTxCoordinatorV0::recover(identity().chain_id, AuthorizedFixture, &mut journal)
            .unwrap();
    let ack = coordinator
        .admit_and_persist(&mut journal, admitted.intent.clone(), 1)
        .unwrap();
    assert_eq!(ack.tx_id, admitted.tx_id);
    drop(journal);
    let mut restarted = open(path);
    let mut coordinator =
        ProductionTxCoordinatorV0::recover(identity().chain_id, AuthorizedFixture, &mut restarted)
            .unwrap();
    assert_eq!(
        coordinator
            .admit_and_persist(&mut restarted, admitted.intent.clone(), 1)
            .unwrap(),
        ack
    );
}

#[test]
fn sigkill_each_real_replacement_write_cut_recovers_the_complete_transaction() {
    for (index, point) in POINTS.into_iter().enumerate() {
        let directory = Directory::new();
        let (journal, previous) = baseline(&directory.0);
        let (replaced, admitted) = pair(&previous);
        drop(journal);
        let marker_directory = Directory::new();
        let ready = marker_directory.0.join("ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "candidate_tx_journal::tests::crash_child",
                "--nocapture",
            ])
            .env("TRNM_TX_TEST_DIRECTORY", &directory.0)
            .env("TRNM_TX_TEST_READY", &ready)
            .env("TRNM_TX_TEST_CUT", index.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("child exited before {point:?}: {status}");
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not reach {point:?}");
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            matches!(
                CandidateTxFileJournalV0::open(
                    &directory.0,
                    identity(),
                    CandidateTxJournalLimitsV0::default()
                ),
                Err(CandidateTxJournalErrorV0::Locked)
            ),
            "live child must exclude a second process owner at {point:?}"
        );
        // std::process::Child::kill sends SIGKILL on Unix. The child cannot
        // run destructors, rollback helpers, flushes or lock cleanup code.
        child.kill().unwrap();
        let status = child.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        assert_atomic_recovery(&directory.0, &previous, &replaced, &admitted, point);
    }
}

#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("TRNM_TX_TEST_DIRECTORY") else {
        return;
    };
    let point = POINTS[std::env::var("TRNM_TX_TEST_CUT")
        .unwrap()
        .parse::<usize>()
        .unwrap()];
    let mut journal = open(Path::new(&path));
    let previous = journal
        .load_latest(identity().chain_id)
        .unwrap()
        .remove(0)
        .record;
    let (replaced, admitted) = pair(&previous);
    journal.fault = Some(Fault { point, park: true });
    journal
        .compare_and_replace(previous.canonical_record_digest_v0(), &replaced, &admitted)
        .unwrap();
    panic!("child failed to reach requested crash cut");
}

#[test]
fn exact_cas_rejects_duplicate_nonce_stale_predecessor_and_single_record_replacement() {
    let directory = Directory::new();
    let (mut journal, previous) = baseline(&directory.0);
    let (replaced, replacement) = pair(&previous);
    assert!(matches!(
        journal.compare_and_append(None, &replacement),
        Err(CandidateTxJournalErrorV0::CompareFailed)
    ));
    assert!(matches!(
        journal.compare_and_append(Some(previous.canonical_record_digest_v0()), &replaced),
        Err(CandidateTxJournalErrorV0::InvalidRecord)
    ));
    assert!(matches!(
        journal.compare_and_replace(Digest32V0([9; 32]), &replaced, &replacement),
        Err(CandidateTxJournalErrorV0::CompareFailed)
    ));
    let mut tampered = replaced.clone();
    tampered.wal_sequence = Some(999);
    assert!(journal
        .compare_and_replace(
            previous.canonical_record_digest_v0(),
            &tampered,
            &replacement
        )
        .is_err());
    assert!(!journal.is_poisoned());
    assert_eq!(
        journal.load_latest(identity().chain_id).unwrap()[0].record,
        previous
    );
}

#[test]
fn private_namespace_lock_and_reopen_fence_competing_owners() {
    let directory = Directory::new();
    let journal = open(&directory.0);
    assert!(matches!(
        CandidateTxFileJournalV0::open(
            &directory.0,
            identity(),
            CandidateTxJournalLimitsV0::default()
        ),
        Err(CandidateTxJournalErrorV0::Locked)
    ));
    let parent = Directory::new();
    let alias = parent.0.join("alias");
    symlink(&directory.0, &alias).unwrap();
    assert!(CandidateTxFileJournalV0::open(
        &alias,
        identity(),
        CandidateTxJournalLimitsV0::default()
    )
    .is_err());
    drop(journal);
    drop(open(&directory.0));
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        CandidateTxFileJournalV0::open(
            &directory.0,
            identity(),
            CandidateTxJournalLimitsV0::default()
        ),
        Err(CandidateTxJournalErrorV0::Namespace)
    ));
}

#[test]
fn changed_lock_inode_and_hardlinked_frames_are_rejected() {
    let directory = Directory::new();
    let (mut journal, _) = baseline(&directory.0);
    fs::rename(directory.0.join(LOCK), directory.0.join("displaced-lock")).unwrap();
    fs::write(directory.0.join(LOCK), []).unwrap();
    fs::set_permissions(directory.0.join(LOCK), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(journal.load_latest(identity().chain_id).is_err());
    assert!(journal.is_poisoned());
    drop(journal);
    fs::remove_file(directory.0.join(LOCK)).unwrap();
    fs::rename(directory.0.join("displaced-lock"), directory.0.join(LOCK)).unwrap();
    let outside = Directory::new();
    fs::hard_link(directory.0.join(frame_name(1)), outside.0.join("alias")).unwrap();
    assert!(matches!(
        CandidateTxFileJournalV0::open(
            &directory.0,
            identity(),
            CandidateTxJournalLimitsV0::default()
        ),
        Err(CandidateTxJournalErrorV0::Namespace)
    ));
}

#[test]
fn corruption_torn_published_frame_and_interior_deletion_fail_closed() {
    for mode in 0..3 {
        let directory = Directory::new();
        let (journal, _) = baseline(&directory.0);
        drop(journal);
        let path = directory.0.join(frame_name(1));
        match mode {
            0 => {
                let mut bytes = fs::read(&path).unwrap();
                bytes[100] ^= 1;
                fs::write(&path, bytes).unwrap();
            }
            1 => {
                let mut bytes = fs::read(&path).unwrap();
                bytes.pop();
                fs::write(&path, bytes).unwrap();
            }
            _ => fs::remove_file(path).unwrap(),
        }
        assert!(CandidateTxFileJournalV0::open(
            &directory.0,
            identity(),
            CandidateTxJournalLimitsV0::default()
        )
        .is_err());
    }
}

#[test]
fn identity_limits_and_all_log_caps_are_enforced_without_eviction() {
    for limits in [
        CandidateTxJournalLimitsV0 {
            maximum_frames: 1,
            ..Default::default()
        },
        CandidateTxJournalLimitsV0 {
            maximum_latest_records: 1,
            ..Default::default()
        },
        CandidateTxJournalLimitsV0 {
            maximum_log_bytes: 512,
            ..Default::default()
        },
    ] {
        let directory = Directory::new();
        let mut journal = CandidateTxFileJournalV0::open(&directory.0, identity(), limits).unwrap();
        let first = admitted(0, 10);
        journal.compare_and_append(None, &first).unwrap();
        assert!(matches!(
            journal.compare_and_append(None, &admitted(1, 10)),
            Err(CandidateTxJournalErrorV0::Capacity)
        ));
        assert_eq!(journal.load_latest(identity().chain_id).unwrap().len(), 1);
        assert!(!journal.is_poisoned());
        drop(journal);
        assert!(CandidateTxFileJournalV0::open(
            &directory.0,
            identity(),
            CandidateTxJournalLimitsV0 {
                maximum_frames: limits.maximum_frames + 1,
                ..limits
            }
        )
        .is_err());
        let mut foreign = identity();
        foreign.journal_id = Digest32V0([8; 32]);
        assert!(CandidateTxFileJournalV0::open(&directory.0, foreign, limits).is_err());
    }
}

#[test]
fn collection_requires_retained_tombstone_and_persists_replay_floor() {
    let directory = Directory::new();
    let (mut journal, previous) = baseline(&directory.0);
    let floor = ReplayFloorWitnessV0 {
        account: previous.intent.sender,
        minimum_replayable_nonce: 1,
        finalized_height: 1,
        authority_digest: Digest32V0([8; 32]),
    };
    assert!(matches!(
        journal.delete_collected(previous.tx_id, previous.canonical_record_digest_v0(), floor),
        Err(CandidateTxJournalErrorV0::CollectionDenied)
    ));
    let (replaced, replacement) = pair(&previous);
    let receipts = journal
        .compare_and_replace(
            previous.canonical_record_digest_v0(),
            &replaced,
            &replacement,
        )
        .unwrap();
    let mut forged_floor = floor;
    forged_floor.account = Digest32V0([9; 32]);
    assert!(matches!(
        journal.delete_collected(
            replaced.tx_id,
            receipts.replaced.record_digest,
            forged_floor
        ),
        Err(CandidateTxJournalErrorV0::CollectionDenied)
    ));
    let receipt = journal
        .delete_collected(replaced.tx_id, receipts.replaced.record_digest, floor)
        .unwrap();
    assert_eq!(
        journal
            .delete_collected(replaced.tx_id, receipts.replaced.record_digest, floor)
            .unwrap(),
        receipt
    );
    let sequence = journal.state.sequence;
    drop(journal);
    let mut journal = open(&directory.0);
    assert_eq!(journal.load_latest(identity().chain_id).unwrap().len(), 1);
    assert_eq!(journal.state.sequence, sequence);
    assert_eq!(
        journal
            .delete_collected(replaced.tx_id, receipts.replaced.record_digest, floor)
            .unwrap(),
        receipt
    );
    assert!(matches!(
        journal.compare_and_append(None, &admitted(0, 30)),
        Err(CandidateTxJournalErrorV0::CompareFailed)
    ));
    assert!(
        directory.0.join(frame_name(1)).is_file(),
        "collection must not compact historical evidence"
    );
}

#[test]
fn idempotent_append_rechecks_identity_head_and_older_receipt_frame() {
    for mode in 0..3 {
        let directory = Directory::new();
        let mut journal = open(&directory.0);
        let first = admitted(0, 10);
        journal.compare_and_append(None, &first).unwrap();
        journal.compare_and_append(None, &admitted(1, 10)).unwrap();
        match mode {
            0 => {
                let path = directory.0.join(frame_name(1));
                let mut bytes = fs::read(&path).unwrap();
                bytes[100] ^= 1;
                fs::write(path, bytes).unwrap();
            }
            1 => fs::remove_file(directory.0.join(frame_name(2))).unwrap(),
            _ => {
                let path = directory.0.join(IDENTITY);
                let mut bytes = fs::read(&path).unwrap();
                bytes[20] ^= 1;
                fs::write(path, bytes).unwrap();
            }
        }
        assert!(journal.compare_and_append(None, &first).is_err());
        assert!(journal.is_poisoned());
        assert!(matches!(
            journal.compare_and_append(None, &first),
            Err(CandidateTxJournalErrorV0::Poisoned)
        ));
    }
}

#[test]
fn idempotent_replacement_and_collection_recheck_their_published_frame() {
    for collect in [false, true] {
        let directory = Directory::new();
        let (mut journal, previous) = baseline(&directory.0);
        let (replaced, replacement) = pair(&previous);
        let receipt = journal
            .compare_and_replace(
                previous.canonical_record_digest_v0(),
                &replaced,
                &replacement,
            )
            .unwrap();
        let floor = ReplayFloorWitnessV0 {
            account: replaced.intent.sender,
            minimum_replayable_nonce: 1,
            finalized_height: 1,
            authority_digest: Digest32V0([8; 32]),
        };
        if collect {
            journal
                .delete_collected(replaced.tx_id, receipt.replaced.record_digest, floor)
                .unwrap();
        }
        let target_sequence = journal.state.sequence;
        journal.compare_and_append(None, &admitted(1, 10)).unwrap();
        fs::remove_file(directory.0.join(frame_name(target_sequence))).unwrap();
        let failed = if collect {
            journal
                .delete_collected(replaced.tx_id, receipt.replaced.record_digest, floor)
                .is_err()
        } else {
            journal
                .compare_and_replace(
                    previous.canonical_record_digest_v0(),
                    &replaced,
                    &replacement,
                )
                .is_err()
        };
        assert!(failed);
        assert!(journal.is_poisoned());
    }
}

#[test]
fn actual_core_phase_and_broadcast_transitions_recover_through_finalized_collection() {
    use trnm_tx_lifecycle_v0::{
        BroadcastReceiptV0, ExecutionReceiptV0, FinalityWitnessV0, OrderedPositionV0,
        ProposalHandoffV0,
    };
    let directory = Directory::new();
    let mut core = TxLifecycleV0::new(identity().chain_id, AuthorizedFixture);
    let tx_id = core.admit(intent(0, 10), 1).unwrap();
    let mut versions = vec![core.record(tx_id).unwrap().clone()];
    core.persist_wal(tx_id, 1).unwrap();
    versions.push(core.record(tx_id).unwrap().clone());
    core.handoff_proposal(
        tx_id,
        ProposalHandoffV0 {
            proposal_id: Digest32V0([4; 32]),
            proposal_index: 0,
        },
    )
    .unwrap();
    versions.push(core.record(tx_id).unwrap().clone());
    let ordered = OrderedPositionV0 {
        block_id: Digest32V0([5; 32]),
        height: 2,
        transaction_index: 0,
    };
    core.mark_ordered(tx_id, ordered).unwrap();
    versions.push(core.record(tx_id).unwrap().clone());
    let execution = ExecutionReceiptV0 {
        tx_id,
        ordered,
        pre_state_root: Digest32V0([6; 32]),
        post_state_root: Digest32V0([7; 32]),
        receipt_digest: Digest32V0([8; 32]),
        event_root: Digest32V0([9; 32]),
        fee_charged: 5,
        success: true,
    };
    core.mark_executed(execution).unwrap();
    versions.push(core.record(tx_id).unwrap().clone());
    let broadcast = core
        .create_broadcast_intent(tx_id, Digest32V0([10; 32]))
        .unwrap();
    versions.push(core.record(tx_id).unwrap().clone());
    core.confirm_broadcast(BroadcastReceiptV0 {
        tx_id,
        intent_sequence: broadcast.intent_sequence,
        envelope_digest: broadcast.envelope_digest,
        transport_receipt_digest: Digest32V0([11; 32]),
    })
    .unwrap();
    versions.push(core.record(tx_id).unwrap().clone());
    core.finalize(
        tx_id,
        FinalityWitnessV0 {
            block_id: ordered.block_id,
            height: ordered.height,
            state_root: execution.post_state_root,
            finality_proof_digest: Digest32V0([12; 32]),
        },
    )
    .unwrap();
    versions.push(core.record(tx_id).unwrap().clone());
    core.tombstone_finalized(tx_id).unwrap();
    versions.push(core.record(tx_id).unwrap().clone());
    let mut previous = None;
    for record in &versions {
        let mut journal = open(&directory.0);
        let receipt = journal.compare_and_append(previous, record).unwrap();
        assert_eq!(
            journal.load_latest(identity().chain_id).unwrap()[0].record,
            *record
        );
        previous = Some(receipt.record_digest);
    }
    let mut journal = open(&directory.0);
    let floor = ReplayFloorWitnessV0 {
        account: intent(0, 10).sender,
        minimum_replayable_nonce: 1,
        finalized_height: 2,
        authority_digest: Digest32V0([13; 32]),
    };
    let mut too_low = floor;
    too_low.finalized_height = 1;
    assert!(matches!(
        journal.delete_collected(tx_id, previous.unwrap(), too_low),
        Err(CandidateTxJournalErrorV0::CollectionDenied)
    ));
    journal.fault = Some(Fault {
        point: Point::ResponseLost,
        park: false,
    });
    assert!(journal
        .delete_collected(tx_id, previous.unwrap(), floor)
        .is_err());
    assert!(journal.is_poisoned());
    drop(journal);
    let mut journal = open(&directory.0);
    assert!(journal.load_latest(identity().chain_id).unwrap().is_empty());
    let receipt = journal
        .delete_collected(tx_id, previous.unwrap(), floor)
        .unwrap();
    assert_ne!(receipt, ZERO);
    assert!(matches!(
        journal.compare_and_append(None, &admitted(0, 30)),
        Err(CandidateTxJournalErrorV0::CompareFailed)
    ));
    journal.compare_and_append(None, &admitted(1, 10)).unwrap();
}

#[test]
fn directory_replacement_poison_fences_the_displaced_owner() {
    let parent = Directory::new();
    let path = parent.0.join("journal");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = open(&path);
    fs::rename(&path, parent.0.join("displaced")).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(
        journal.compare_and_append(None, &admitted(0, 10)),
        Err(CandidateTxJournalErrorV0::Namespace)
    ));
    assert!(journal.is_poisoned());
    assert!(!parent.0.join("displaced").join(frame_name(1)).exists());
}

#[test]
fn replacement_of_synced_stage_or_published_inode_never_returns_an_ack() {
    for point in [Point::FileSynced, Point::Published, Point::DirectorySynced] {
        let directory = Directory::new();
        let (mut journal, previous) = baseline(&directory.0);
        let (replaced, admitted) = pair(&previous);
        journal.publication_attack = Some(PublicationAttack {
            point,
            replace_inode: true,
        });
        assert!(
            matches!(
                journal.compare_and_replace(
                    previous.canonical_record_digest_v0(),
                    &replaced,
                    &admitted
                ),
                Err(CandidateTxJournalErrorV0::Namespace)
            ),
            "{point:?}"
        );
        assert!(journal.is_poisoned());
        assert!(
            journal.publication_attack.is_none(),
            "the swap must really run"
        );
        fs::remove_file(directory.0.join("test-displaced-publication")).unwrap();
        drop(journal);
        // A pre-publish attack leaves only an unpublished stage. An identical
        // post-publish replacement retains the whole pair, never one member.
        // Reopen and exact retry reconcile the uncertain, unacknowledged cut.
        assert_atomic_recovery(&directory.0, &previous, &replaced, &admitted, point);
    }
}

#[test]
fn same_inode_content_changes_are_rejected_before_ack_and_fail_closed_on_reopen() {
    for point in [Point::FileSynced, Point::Published, Point::DirectorySynced] {
        let directory = Directory::new();
        let (mut journal, previous) = baseline(&directory.0);
        let (replaced, admitted) = pair(&previous);
        journal.publication_attack = Some(PublicationAttack {
            point,
            replace_inode: false,
        });
        assert!(
            matches!(
                journal.compare_and_replace(
                    previous.canonical_record_digest_v0(),
                    &replaced,
                    &admitted
                ),
                Err(CandidateTxJournalErrorV0::Corrupt(
                    "written file bytes changed"
                ))
            ),
            "{point:?}"
        );
        assert!(journal.is_poisoned());
        assert!(
            journal.publication_attack.is_none(),
            "the tamper must really run"
        );
        drop(journal);
        if point == Point::FileSynced {
            assert_atomic_recovery(&directory.0, &previous, &replaced, &admitted, point);
        } else {
            assert!(matches!(
                CandidateTxFileJournalV0::open(
                    &directory.0,
                    identity(),
                    CandidateTxJournalLimitsV0::default()
                ),
                Err(CandidateTxJournalErrorV0::Corrupt(_))
            ));
        }
    }
}
