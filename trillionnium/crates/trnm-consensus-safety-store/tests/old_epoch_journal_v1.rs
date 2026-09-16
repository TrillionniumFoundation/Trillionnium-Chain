#![cfg(target_os = "linux")]
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
use tempfile::TempDir;
use trnm_consensus_core::{
    minimum_old_epoch_boundary_record_limits_v1, minimum_safety_state_record_limits_v0, Core,
    CoreConfig, Effect, Input, OldEpochBoundaryCoreV1, SafetyStatePersistenceV0,
    SafetyStateRecordLimitsV0,
};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_safety_store::*;
use trnm_consensus_types::*;
static PROCESS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn config() -> CoreConfig {
    let p = ConsensusParametersV0::reference_shadow_v0();
    let validators = (1..=4)
        .map(|id| {
            Validator::new(
                ValidatorId::new([id; 32]),
                ConsensusPublicKey::new(
                    ed25519_dalek::SigningKey::from_bytes(&[id; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                VotingPower::new(1).unwrap(),
            )
            .unwrap()
        })
        .collect();
    let set = ValidatorSet::new(
        GenesisHash::new([0xa5; 32]),
        ChainId::from_static("journal8-test"),
        ProtocolVersion::V0,
        Epoch::new(0),
        p.hash(),
        validators,
    )
    .unwrap();
    CoreConfig::new(ValidatorId::new([1; 32]), set, p, 0, 16, 16).unwrap()
}
fn profiles() -> (SafetyStateStoreProfileV0, OldEpochSafetyJournalProfileV1) {
    let config = config();
    let l = minimum_safety_state_record_limits_v0(&config).unwrap();
    let source = SafetyStateStoreProfileV0::new(
        config.clone(),
        [0x73; 32],
        l,
        l.maximum_record_bytes() * 4 + 16 * 1024 * 1024,
    )
    .unwrap();
    let limits = minimum_old_epoch_boundary_record_limits_v1(&config).unwrap();
    let outgoing = OldEpochSafetyJournalProfileV1::new(source.clone(), limits, 1).unwrap();
    (source, outgoing)
}
fn request(effects: &[Effect]) -> SafetyStatePersistenceV0 {
    effects
        .iter()
        .find_map(|e| {
            if let Effect::PersistSafetyState(r) = e {
                Some(r.clone())
            } else {
                None
            }
        })
        .unwrap()
}
fn core() -> Core {
    let c = config();
    let g = GenesisQcV0::new(
        c.validator_set().genesis_hash(),
        c.validator_set().chain_id(),
        c.validator_set(),
    )
    .unwrap();
    Core::new(c, g, &StrictEd25519Verifier).unwrap()
}
fn dir() -> TempDir {
    let d = TempDir::new().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
fn initialize(
    path: &Path,
) -> (
    SqliteSafetyStateStoreV0<StrictEd25519Verifier>,
    SqliteOldEpochSafetyJournalV1,
    OldEpochBoundaryCoreV1,
    OldEpochSafetyHeadPinV1,
) {
    let (old_profile, new_profile) = profiles();
    let c = core();
    let source = SqliteSafetyStateStoreV0::initialize_new(
        path.join("old.db"),
        old_profile,
        StrictEd25519Verifier,
        c.safety_state(),
    )
    .unwrap();
    let old = source.head().unwrap();
    let (mut owner, effects) = c.into_old_epoch_boundary_v1(1).unwrap();
    let migration = request(&effects);
    let (store, confirmed) = SqliteOldEpochSafetyJournalV1::initialize_from_journal7_v1(
        path.join("new.db"),
        new_profile,
        &source,
        old.chain_checksum(),
        &owner,
        &migration,
    )
    .unwrap();
    let pin = confirmed.pin_v1();
    assert_eq!(
        store.fresh_read_v1(pin).unwrap().state_v1(),
        migration.state()
    );
    assert!(owner
        .step_v1(Input::StorageAck {
            barrier: migration.barrier()
        })
        .unwrap()
        .is_empty());
    (source, store, owner, pin)
}
// Keep the real WAL/SHM namespace intact: these mutants test content
// validation, rather than succeeding merely because a sidecar disappeared.
fn tamper_connection(path: &Path) -> rusqlite::Connection {
    let c = rusqlite::Connection::open(path).unwrap();
    let mut persist = 1i32;
    let code = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            c.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
            (&mut persist as *mut i32).cast(),
        )
    };
    assert_eq!(code, rusqlite::ffi::SQLITE_OK);
    assert_eq!(persist, 1);
    c
}
fn read_pin(path: &Path) -> OldEpochSafetyHeadPinV1 {
    let c = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    c.query_row(
        "SELECT m.journal,h.revision,h.chain FROM outgoing_metadata m CROSS JOIN outgoing_head h",
        [],
        |r| {
            Ok(OldEpochSafetyHeadPinV1 {
                journal_id: r.get(0)?,
                revision: r.get(1)?,
                chain_checksum: r.get(2)?,
            })
        },
    )
    .unwrap()
}
fn timeout(owner: &mut OldEpochBoundaryCoreV1) -> SafetyStatePersistenceV0 {
    request(
        &owner
            .step_v1(Input::LocalTimeout {
                epoch: Epoch::new(0),
                view: owner.safety_state().current_view(),
            })
            .unwrap(),
    )
}

#[test]
fn strict_migration_append_retry_and_readonly_reopen() {
    let _g = PROCESS_LOCK.lock().unwrap();
    let d = dir();
    let (source, mut store, mut owner, pin) = initialize(d.path());
    assert!(store.prepare_terminal_recovery_v1(pin).is_err());
    let source_before = source.head().unwrap();
    let r = timeout(&mut owner);
    let result = store
        .persist_exact_v1(pin, &r, &SafetyTransitionContextV0::Ordinary)
        .unwrap();
    assert_eq!(result.revision_v1(), pin.revision + 1);
    assert_eq!(result.state_v1(), r.state());
    assert!(result.belongs_to_store_at_path_v1(&store, store.path_v1()));
    let next = result.pin_v1();
    assert!(store.prepare_terminal_recovery_v1(next).is_err());
    assert_eq!(
        store
            .persist_exact_v1(next, &r, &SafetyTransitionContextV0::Ordinary)
            .unwrap()
            .pin_v1(),
        next
    );
    assert_eq!(source.head().unwrap(), source_before);
    drop(store);
    assert!(SqliteOldEpochSafetyJournalV1::open_existing_v1(
        d.path().join("new.db"),
        profiles().1,
        pin
    )
    .is_err());
    let mut reopened = SqliteOldEpochSafetyJournalV1::open_existing_v1(
        d.path().join("new.db"),
        profiles().1,
        next,
    )
    .unwrap();
    assert_eq!(reopened.fresh_read_v1(next).unwrap().state_v1(), r.state());
    assert!(!result.belongs_to_store_at_path_v1(&reopened, reopened.path_v1()));
    assert!(reopened
        .persist_exact_v1(next, &r, &SafetyTransitionContextV0::Ordinary)
        .is_err());
}
#[test]
fn missing_namespace_wrong_profile_and_foreign_core_are_rejected() {
    let _g = PROCESS_LOCK.lock().unwrap();
    let d = dir();
    let (_source, mut store, mut owner, pin) = initialize(d.path());
    assert!(SqliteOldEpochSafetyJournalV1::open_existing_v1(
        d.path().join("new.db"),
        profiles().1,
        pin
    )
    .is_err());
    let (foreign, effects) = core().into_old_epoch_boundary_v1(1).unwrap();
    drop(foreign);
    assert!(store
        .persist_exact_v1(
            pin,
            &request(&effects),
            &SafetyTransitionContextV0::Ordinary
        )
        .is_err());
    // Owner-affinity rejection occurs before touching/fencing the real head.
    store
        .persist_exact_v1(
            pin,
            &timeout(&mut owner),
            &SafetyTransitionContextV0::Ordinary,
        )
        .unwrap();
    drop(store);
    let missing = d.path().join("missing.db");
    assert!(SqliteOldEpochSafetyJournalV1::open_existing_v1(&missing, profiles().1, pin).is_err());
    assert!(!missing.exists());
}
#[test]
fn failed_source_pin_creates_nothing_and_journal7_stays_schema13() {
    let _g = PROCESS_LOCK.lock().unwrap();
    let d = dir();
    let (profile, new) = profiles();
    let c = core();
    let source = SqliteSafetyStateStoreV0::initialize_new(
        d.path().join("old.db"),
        profile,
        StrictEd25519Verifier,
        c.safety_state(),
    )
    .unwrap();
    let (owner, effects) = c.into_old_epoch_boundary_v1(1).unwrap();
    let target = d.path().join("new.db");
    assert!(SqliteOldEpochSafetyJournalV1::initialize_from_journal7_v1(
        &target,
        new,
        &source,
        [0; 32],
        &owner,
        &request(&effects)
    )
    .is_err());
    assert!(!target.exists());
    assert_eq!(source.head().unwrap().state().schema_version(), 13);
}
#[test]
fn corruption_and_missing_sidecars_never_repair() {
    let _g = PROCESS_LOCK.lock().unwrap();
    for mutation in 0..4 {
        let d = dir();
        let (_source, store, _owner, pin) = initialize(d.path());
        drop(store);
        let p = d.path().join("new.db");
        match mutation {
            0 => {
                let c = tamper_connection(&p);
                c.execute(
                    "UPDATE outgoing_records SET record=zeroblob(length(record))",
                    [],
                )
                .unwrap();
            }
            1 => {
                let c = tamper_connection(&p);
                c.execute_batch("CREATE TRIGGER alien AFTER UPDATE ON outgoing_head BEGIN DELETE FROM outgoing_records; END;").unwrap();
            }
            2 => {
                fs::remove_file(d.path().join("new.db.outgoing.lock")).unwrap();
            }
            _ => {
                fs::remove_file(d.path().join("new.db-wal")).unwrap();
            }
        }
        assert!(
            SqliteOldEpochSafetyJournalV1::open_existing_v1(&p, profiles().1, pin).is_err(),
            "mutation {mutation}"
        );
        if mutation == 2 {
            assert!(!d.path().join("new.db.outgoing.lock").exists());
        }
        if mutation == 3 {
            assert!(!d.path().join("new.db-wal").exists());
        }
    }
}
#[test]
fn journal8_crash_child() {
    let Ok(directory) = std::env::var("TRNM_JOURNAL8_KILL_DIRECTORY") else {
        return;
    };
    let cut: usize = std::env::var("TRNM_JOURNAL8_KILL_CUT")
        .unwrap()
        .parse()
        .unwrap();
    let (_source, mut store, mut owner, pin) = initialize(Path::new(&directory));
    let r = timeout(&mut owner);
    let selected = [
        OldEpochJournalCutV1::AfterWriteBeforeCommit,
        OldEpochJournalCutV1::AfterCommitBeforeSync,
        OldEpochJournalCutV1::AfterSyncBeforeReadback,
    ][cut];
    let _ =
        store.persist_with_observer_v1(pin, &r, &SafetyTransitionContextV0::Ordinary, |point| {
            if point == selected {
                unsafe {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                }
            }
            Ok(())
        });
    panic!("crash cut was not reached");
}
#[test]
fn actual_sigkill_preserves_predecessor_or_exact_successor() {
    let _g = PROCESS_LOCK.lock().unwrap();
    for cut in 0..3 {
        let d = dir();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "journal8_crash_child", "--nocapture"])
            .env("TRNM_JOURNAL8_KILL_DIRECTORY", d.path())
            .env("TRNM_JOURNAL8_KILL_CUT", cut.to_string())
            .status()
            .unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let p = d.path().join("new.db");
        let pin = read_pin(&p);
        assert_eq!(pin.revision, if cut == 0 { 1 } else { 2 });
        let reopened =
            SqliteOldEpochSafetyJournalV1::open_existing_v1(&p, profiles().1, pin).unwrap();
        assert_eq!(
            reopened
                .fresh_read_v1(pin)
                .unwrap()
                .state_v1()
                .pending_sign()
                .is_some(),
            cut != 0
        );
    }
}
#[test]
fn insufficient_limits_are_rejected_before_file_creation() {
    let _g = PROCESS_LOCK.lock().unwrap();
    let (source, _) = profiles();
    assert!(OldEpochSafetyJournalProfileV1::new(
        source,
        SafetyStateRecordLimitsV0::new(128, 128).unwrap(),
        1
    )
    .is_err());
}

#[test]
fn retained_head_still_binds_origin_after_first_record_is_pruned() {
    use ed25519_dalek::Signer;
    let _g = PROCESS_LOCK.lock().unwrap();
    let d = dir();
    let (_source, mut store, mut owner, pin) = initialize(d.path());
    let r = timeout(&mut owner);
    let pending = r.state().clone();
    let next = store
        .persist_exact_v1(pin, &r, &SafetyTransitionContextV0::Ordinary)
        .unwrap()
        .pin_v1();
    let released = owner
        .step_v1(Input::StorageAck {
            barrier: r.barrier(),
        })
        .unwrap();
    let intent = released
        .iter()
        .find_map(|e| {
            if let Effect::RequestSignature { intent } = e {
                Some(intent)
            } else {
                None
            }
        })
        .unwrap();
    let root = intent.signing_root();
    let signature = ed25519_dalek::SigningKey::from_bytes(&[1; 32])
        .sign(root.as_bytes())
        .to_bytes();
    owner
        .step_v1(Input::SignatureReady {
            id: trnm_consensus_core::SignId::new(root),
            signature: Signature64::new(signature.to_vec()).unwrap(),
        })
        .unwrap();
    let cleanup = request(&owner.persist_signature_release_v1(&pending).unwrap());
    let current = store
        .persist_exact_v1(next, &cleanup, &SafetyTransitionContextV0::Ordinary)
        .unwrap()
        .pin_v1();
    assert_eq!(current.revision, 3);
    drop(store);
    let p = d.path().join("new.db");
    // A malicious rewrite recomputes internally self-consistent metadata, but
    // cannot change the independently pinned active chain to match that origin.
    let c = tamper_connection(&p);
    let count: u64 = c
        .query_row(
            "SELECT count(*) FROM outgoing_records WHERE revision=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    use sha2::{Digest, Sha256};
    type OriginParts = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let (profile,journal,source_journal,source_record,source_context):OriginParts=c.query_row("SELECT profile,journal,source_journal,source_record,source_transition FROM outgoing_metadata",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
    let false_source_chain = [0u8; 32];
    let mut h = Sha256::new();
    h.update(b"trnm.journal8.outgoing.origin.v1");
    for part in [
        profile.as_slice(),
        journal.as_slice(),
        source_journal.as_slice(),
        false_source_chain.as_slice(),
        source_record.as_slice(),
        source_context.as_slice(),
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    let forged_origin: [u8; 32] = h.finalize().into();
    c.execute(
        "UPDATE outgoing_metadata SET origin=?1,source_chain=?2",
        rusqlite::params![forged_origin.as_slice(), false_source_chain.as_slice()],
    )
    .unwrap();
    drop(c);
    assert!(SqliteOldEpochSafetyJournalV1::open_existing_v1(&p, profiles().1, current).is_err());
}
