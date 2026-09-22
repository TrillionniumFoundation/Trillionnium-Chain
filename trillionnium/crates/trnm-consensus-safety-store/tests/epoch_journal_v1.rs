#![cfg(all(target_os = "linux", feature = "test-fixtures"))]
use ed25519_dalek::{Signer, SigningKey};
use trnm_consensus_safety_store::test_fixtures::*;
use trnm_consensus_types::SignatureBytes;
#[test]
fn actual_native_core_and_journal8_reach_the_same_terminal_cut() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = SigningKey::from_bytes(&[20; 32]);
    let fixture = build_native_old_epoch_terminal_v1(dir.path(), |intent| {
        Ok(SignatureBytes::from_array(
            key.sign(intent.signing_root().as_bytes()).to_bytes(),
        ))
    })
    .unwrap();
    assert_eq!(fixture.sign_intents.len(), 10);
    assert_eq!(
        fixture
            .source_journal
            .head()
            .unwrap()
            .state()
            .last_voted_view(),
        None
    );
    assert_eq!(
        fixture
            .owner
            .safety_state()
            .last_voted_view()
            .unwrap()
            .get(),
        10
    );
    assert_eq!(
        fixture
            .application
            .confirmed_committed_head_v0()
            .unwrap()
            .height()
            .get(),
        8
    );
    assert_eq!(
        fixture
            .journal
            .fresh_read_v1(fixture.pin)
            .unwrap()
            .state_v1(),
        fixture.owner.safety_state()
    );
}
use std::{os::unix::fs::PermissionsExt, path::Path};
use trnm_consensus_core::*;
use trnm_consensus_crypto::*;
use trnm_consensus_safety_store::*;
use trnm_consensus_types::*;

fn actual_fixture(path: &Path) -> Box<NativeOldEpochTerminalFixtureV1> {
    let key = SigningKey::from_bytes(&[20; 32]);
    Box::new(
        build_native_old_epoch_terminal_v1(path, |intent| {
            Ok(SignatureBytes::from_array(
                key.sign(intent.signing_root().as_bytes()).to_bytes(),
            ))
        })
        .unwrap(),
    )
}
fn activation(f: &NativeOldEpochTerminalFixtureV1) -> StrictEpochRuntimeContextV1 {
    // Borrow the separate prepared checkpoint for actual COMMITTED readback;
    // no capability is recreated from public scalar fields.
    let prepared = f
        .application
        .confirm_prepared_checkpoint_execution_v1(&f.checkpoint, &f.checkpoint_execution)
        .unwrap();
    let proof = decode_finality_proof_v0_exact(
        &f.checkpoint_finality_bytes,
        prepared.old_validator_set(),
        prepared.old_parameters(),
        7000,
    )
    .unwrap();
    let anchor = decode_epoch_anchor_authorization_kernel_v0_exact(
        &f.handoff_anchor_bytes,
        prepared.old_validator_set(),
        prepared.new_validator_set(),
    )
    .unwrap();
    let parent = f
        .owner
        .safety_state()
        .last_finalization()
        .unwrap()
        .authenticated_parent();
    assert_eq!(parent.height().get(), 7);
    // The real preparation retains the fully signed authenticated parent.
    let evidence = &f.checkpoint_parent_header;
    let strict = verify_same_version_epoch_activation_authority_strict_v0(
        &proof,
        &prepared.next_epoch_commitment(),
        &anchor,
        prepared.old_validator_set(),
        prepared.old_parameters(),
        prepared.new_validator_set(),
        prepared.new_parameters(),
        evidence,
    )
    .unwrap();
    StrictEpochRuntimeContextV1::from_activation_v1(strict).unwrap()
}
fn prepare(
    f: &NativeOldEpochTerminalFixtureV1,
) -> (
    EpochSafetyJournalProfileV1,
    Box<PreparedEpochCoreActivationV1>,
) {
    let runtime = activation(f);
    let config = CoreConfig::new(
        runtime
            .structural_context()
            .new_validator_set()
            .validators()[0]
            .id(),
        runtime.structural_context().new_validator_set().clone(),
        *runtime.structural_context().new_parameters(),
        0,
        32,
        64,
    )
    .unwrap();
    let row = f
        .application
        .confirm_durable_execution_history_row_v0(&f.checkpoint_execution)
        .unwrap();
    let h = f.checkpoint.header();
    let artifact = ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(h.id(), h.parent_id(), row.overlay_digest_v0()),
        row.artifact_digest_v0(),
    );
    let limits = minimum_epoch_safety_record_limits_v1(&config, &runtime).unwrap();
    let context =
        EpochSafetyStateRecordContextV1::new(&config, runtime, artifact, 2, limits).unwrap();
    let profile = EpochSafetyJournalProfileV1::new(f.profile.clone(), &context).unwrap();
    let (_, terminal) = f.journal.prepare_terminal_recovery_v1(f.pin).unwrap();
    (
        profile,
        Box::new(terminal.prepare_epoch_activation_v1(&context).unwrap()),
    )
}
#[test]
fn journal9_actual_source_exact_retry_strict_reopen_and_foreign_affinity() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let f = actual_fixture(&dir.path().join("chain"));
    let (profile, prepared) = prepare(&f);
    let path = dir.path().join("epoch9.db");
    let (mut journal, head) = SqliteEpochSafetyJournalV1::initialize_from_journal8_v1(
        &path,
        profile.clone(),
        &f.journal,
        f.pin,
        &prepared,
    )
    .unwrap();
    let pin = head.pin_v1();
    assert_eq!(head.state_v1(), prepared.state());
    assert!(head.belongs_to_store_at_path_v1(&journal, &path));
    assert_eq!(
        journal
            .persist_exact_v1(
                pin,
                prepared.initial_persistence_v1(),
                &SafetyTransitionContextV0::ordinary()
            )
            .unwrap()
            .pin_v1(),
        pin
    );
    let (_, foreign) = prepare(&f);
    assert!(journal
        .persist_exact_v1(
            pin,
            foreign.initial_persistence_v1(),
            &SafetyTransitionContextV0::ordinary()
        )
        .is_err());
    drop(journal);
    let reopened = SqliteEpochSafetyJournalV1::open_existing_v1(&path, profile, pin).unwrap();
    assert!(!head.belongs_to_store_at_path_v1(&reopened, &path));
    let (fresh, inert) = reopened.prepare_recovery_v1(pin).unwrap();
    assert_eq!(inert.state(), prepared.state());
    assert_eq!(inert.record_checksum(), fresh.state_record_checksum_v1());
    let stale = EpochSafetyHeadPinV1 {
        revision: pin.revision + 1,
        ..pin
    };
    assert!(reopened.fresh_read_v1(stale).is_err());
}

#[test]
fn journal9_reused_read_context_never_reuses_live_acceptance() {
    use sha2::{Digest, Sha256};

    let dir = directory();
    let f = actual_fixture(&dir.path().join("chain"));
    let (profile, prepared) = prepare(&f);
    let path = dir.path().join("epoch9.db");
    let (journal, head) = SqliteEpochSafetyJournalV1::initialize_from_journal8_v1(
        &path, profile, &f.journal, f.pin, &prepared,
    )
    .unwrap();
    let pin = head.pin_v1();
    assert_eq!(
        journal.fresh_read_v1(pin).unwrap().state_v1(),
        prepared.state()
    );

    // Keep the mutator connection alive so the negative exercises durable
    // contents, not a WAL/SHM inode replacement caused by last-close cleanup.
    let mut writer = rusqlite::Connection::open(&path).unwrap();
    let (origin, source_chain): ([u8; 32], [u8; 32]) = writer
        .query_row("SELECT origin,source_chain FROM epoch_metadata", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    writer
        .execute(
            "UPDATE epoch_metadata SET source_chain=?1",
            [[0x55u8; 32].as_slice()],
        )
        .unwrap();
    assert!(matches!(
        journal.fresh_read_v1(pin),
        Err(EpochJournalErrorV1::Invalid(
            "metadata profile/source binding"
        ))
    ));
    writer
        .execute(
            "UPDATE epoch_metadata SET source_chain=?1",
            [source_chain.as_slice()],
        )
        .unwrap();
    assert_eq!(journal.fresh_read_v1(pin).unwrap().pin_v1(), pin);

    // A valid outer hash and caller pin do not authenticate transition bytes.
    // Recompute both to force the strict decoder, rather than just a stale-pin
    // or checksum error, after a successful read on this same journal owner.
    let (predecessor, record, transition): ([u8; 32], Vec<u8>, Vec<u8>) = writer
        .query_row(
            "SELECT predecessor,record,transition FROM epoch_records WHERE revision=?1",
            [pin.revision],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let bad_transition = [0xffu8];
    let revision = pin.revision.to_be_bytes();
    let parts: [&[u8]; 5] = [&origin, &predecessor, &revision, &record, &bad_transition];
    let mut hash = Sha256::new();
    hash.update(b"trnm.journal9.epoch.chain.v1");
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    let bad_chain: [u8; 32] = hash.finalize().into();
    {
        let tx = writer.transaction().unwrap();
        tx.execute(
            "UPDATE epoch_records SET chain=?1,transition=?2 WHERE revision=?3",
            rusqlite::params![
                bad_chain.as_slice(),
                bad_transition.as_slice(),
                pin.revision
            ],
        )
        .unwrap();
        tx.execute("UPDATE epoch_head SET chain=?1", [bad_chain.as_slice()])
            .unwrap();
        tx.commit().unwrap();
    }
    let bad_pin = EpochSafetyHeadPinV1 {
        chain_checksum: bad_chain,
        ..pin
    };
    assert!(matches!(
        journal.fresh_read_v1(bad_pin),
        Err(EpochJournalErrorV1::Source(_))
    ));
    {
        let tx = writer.transaction().unwrap();
        tx.execute(
            "UPDATE epoch_records SET chain=?1,transition=?2 WHERE revision=?3",
            rusqlite::params![pin.chain_checksum.as_slice(), transition, pin.revision],
        )
        .unwrap();
        tx.execute(
            "UPDATE epoch_head SET chain=?1",
            [pin.chain_checksum.as_slice()],
        )
        .unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        journal.fresh_read_v1(pin).unwrap().state_v1(),
        prepared.state()
    );
}

#[cfg(feature = "candidate-epoch-host-v1")]
#[test]
fn journal9_initial_host_recovery_fresh_binds_then_persists_real_timeout() {
    let dir = directory();
    let f = actual_fixture(&dir.path().join("chain"));
    let (profile, prepared) = prepare(&f);
    let path = dir.path().join("epoch9.db");
    let (journal, head) = SqliteEpochSafetyJournalV1::initialize_from_journal8_v1(
        &path,
        profile.clone(),
        &f.journal,
        f.pin,
        &prepared,
    )
    .unwrap();
    let pin = head.pin_v1();
    let source = f.journal.fresh_read_v1(f.pin).unwrap();
    assert_eq!(head.migration_source_v1().pin_v1(), f.pin);
    assert_eq!(
        head.migration_source_v1().state_record_checksum_v1(),
        source.state_record_checksum_v1()
    );
    assert_eq!(
        head.migration_source_v1().context_ref_v1(),
        source.context_ref_v1()
    );
    assert_eq!(
        head.migration_source_v1().profile_ref_v1(),
        f.profile.profile_ref_v1()
    );
    assert_eq!(
        head.migration_source_v1().initial_revision_v1(),
        pin.revision
    );
    let old_request = prepared.initial_persistence_v1().clone();
    journal
        .confirm_exact_request_v1(pin, &old_request, &SafetyTransitionContextV0::ordinary())
        .unwrap();
    drop(journal);
    drop(prepared);
    let mut reopened =
        SqliteEpochSafetyJournalV1::open_existing_v1(&path, profile.clone(), pin).unwrap();
    assert!(reopened
        .confirm_exact_request_v1(pin, &old_request, &SafetyTransitionContextV0::ordinary())
        .is_err());
    assert!(reopened
        .prepare_candidate_host_initial_recovery_v1(EpochSafetyHeadPinV1 {
            revision: pin.revision + 1,
            ..pin
        })
        .is_err());
    let (fresh, mut pending) = reopened
        .prepare_candidate_host_initial_recovery_v1(pin)
        .unwrap();
    assert!(fresh.belongs_to_store_at_path_v1(&reopened, &path));
    assert!(!head.belongs_to_store_at_path_v1(&reopened, &path));
    assert!(pending.activation_persistence_pending_v1());
    assert!(reopened
        .prepare_candidate_host_initial_recovery_v1(pin)
        .is_err());
    assert!(reopened
        .confirm_exact_request_v1(pin, &old_request, &SafetyTransitionContextV0::ordinary())
        .is_err());
    reopened
        .confirm_exact_request_v1(
            pin,
            pending.initial_persistence_v1(),
            &SafetyTransitionContextV0::ordinary(),
        )
        .unwrap();
    assert!(matches!(
        pending.step_v1(Input::Resume),
        Err(CoreError::EpochActivationPersistencePending)
    ));
    // Test supplies the ordinary trusted-host ACK only to exercise the engine;
    // this test does not claim an external node checkpoint or signer lease join.
    assert_eq!(
        pending
            .step_v1(Input::StorageAck {
                barrier: pending.initial_persistence_v1().barrier()
            })
            .unwrap(),
        vec![Effect::ArmViewTimer {
            epoch: Epoch::new(1),
            view: View::new(1)
        }]
    );
    let before = pending.state().clone();
    let effects = pending
        .step_v1(Input::LocalTimeout {
            epoch: Epoch::new(1),
            view: View::new(1),
        })
        .unwrap();
    let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
        panic!("timeout must persist before signing")
    };
    assert!(request.state().pending_sign().is_some());
    Core::validate_persisted_successor_v0(
        pending.config(),
        &before,
        request.state(),
        &StrictEd25519Verifier,
    )
    .unwrap();
    let appended = reopened
        .persist_exact_v1(pin, request, &SafetyTransitionContextV0::ordinary())
        .unwrap();
    let next = appended.pin_v1();
    reopened
        .confirm_exact_request_v1(next, request, &SafetyTransitionContextV0::ordinary())
        .unwrap();
    assert!(!fresh.belongs_to_store_at_path_v1(&reopened, &path));
    assert!(matches!(
        pending
            .step_v1(Input::StorageAck {
                barrier: request.barrier()
            })
            .unwrap()
            .as_slice(),
        [Effect::RequestSignature { .. }]
    ));
    drop(pending);
    drop(reopened);
    let mut progressed =
        SqliteEpochSafetyJournalV1::open_existing_v1(&path, profile, next).unwrap();
    assert!(progressed
        .prepare_candidate_host_initial_recovery_v1(next)
        .is_err());
    assert!(progressed
        .fresh_read_v1(next)
        .unwrap()
        .state_v1()
        .pending_sign()
        .is_some());
}

fn profile_for_artifact(
    f: &NativeOldEpochTerminalFixtureV1,
    artifact: ValidatedPayloadArtifactRefV0,
) -> EpochSafetyJournalProfileV1 {
    let runtime = activation(f);
    let config = CoreConfig::new(
        runtime
            .structural_context()
            .new_validator_set()
            .validators()[0]
            .id(),
        runtime.structural_context().new_validator_set().clone(),
        *runtime.structural_context().new_parameters(),
        0,
        32,
        64,
    )
    .unwrap();
    let limits = minimum_epoch_safety_record_limits_v1(&config, &runtime).unwrap();
    let context =
        EpochSafetyStateRecordContextV1::new(&config, runtime, artifact, 2, limits).unwrap();
    EpochSafetyJournalProfileV1::new(f.profile.clone(), &context).unwrap()
}
fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
#[test]
fn journal9_rejects_wrong_source_profile_and_corrupt_retained_origin() {
    let dir = directory();
    let f = actual_fixture(&dir.path().join("chain"));
    let (profile, prepared) = prepare(&f);
    let path = dir.path().join("epoch9.db");
    let wrong_source = OldEpochSafetyHeadPinV1 {
        revision: f.pin.revision - 1,
        ..f.pin
    };
    assert!(SqliteEpochSafetyJournalV1::initialize_from_journal8_v1(
        &path,
        profile.clone(),
        &f.journal,
        wrong_source,
        &prepared
    )
    .is_err());
    assert!(!path.exists());
    let bad_artifact = ValidatedPayloadArtifactRefV0::new(
        prepared
            .state()
            .epoch_state_v1()
            .unwrap()
            .checkpoint_artifact()
            .overlay(),
        [0xab; 32],
    );
    let wrong_profile = profile_for_artifact(&f, bad_artifact);
    assert!(SqliteEpochSafetyJournalV1::initialize_from_journal8_v1(
        &path,
        wrong_profile.clone(),
        &f.journal,
        f.pin,
        &prepared
    )
    .is_err());
    assert!(!path.exists());
    let (store, head) = SqliteEpochSafetyJournalV1::initialize_from_journal8_v1(
        &path,
        profile.clone(),
        &f.journal,
        f.pin,
        &prepared,
    )
    .unwrap();
    let pin = head.pin_v1();
    drop(store);
    assert!(SqliteEpochSafetyJournalV1::open_existing_v1(&path, wrong_profile, pin).is_err());
    let c = rusqlite::Connection::open(&path).unwrap();
    let mut persist = 1i32;
    // Keep the actual WAL namespace: rejection must be due to authenticated
    // origin content, not SQLite deleting a sidecar when this handle closes.
    assert_eq!(
        unsafe {
            rusqlite::ffi::sqlite3_file_control(
                c.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
                (&mut persist as *mut i32).cast(),
            )
        },
        rusqlite::ffi::SQLITE_OK
    );
    c.execute(
        "UPDATE epoch_metadata SET source_chain=?1",
        [[0x91u8; 32].as_slice()],
    )
    .unwrap();
    drop(c);
    assert!(SqliteEpochSafetyJournalV1::open_existing_v1(&path, profile, pin).is_err());
}
const CHILD_DIR: &str = "TRNM_JOURNAL9_CHILD_DIR";
const CHILD_CUT: &str = "TRNM_JOURNAL9_CHILD_CUT";
#[test]
fn journal9_initialization_crash_child() {
    let Ok(path) = std::env::var(CHILD_DIR) else {
        return;
    };
    let cut: usize = std::env::var(CHILD_CUT).unwrap().parse().unwrap();
    let path = Path::new(&path);
    let f = actual_fixture(&path.join("chain"));
    let (profile, prepared) = prepare(&f);
    let artifact = prepared
        .state()
        .epoch_state_v1()
        .unwrap()
        .checkpoint_artifact();
    SqliteEpochSafetyJournalV1::initialize_with_observer_v1(
        path.join("epoch9.db"),
        profile,
        &f.journal,
        f.pin,
        &prepared,
        |at, pin| {
            let index = match at {
                EpochJournalCutV1::AfterWriteBeforeCommit => 0,
                EpochJournalCutV1::AfterCommitBeforeSync => 1,
                EpochJournalCutV1::AfterSyncBeforeReadback => 2,
            };
            if index == cut {
                use std::io::Write;
                // Test-controlled independent comparison pin, not a recovery grant.
                let mut bytes = Vec::new();
                bytes.extend(pin.journal_id);
                bytes.extend(pin.revision.to_le_bytes());
                bytes.extend(pin.chain_checksum);
                bytes.extend(artifact.overlay().overlay_checksum());
                bytes.extend(artifact.source_artifact_checksum());
                let mut file = std::fs::File::create(path.join("independent-cut")).unwrap();
                file.write_all(&bytes).unwrap();
                file.sync_all().unwrap();
                unsafe {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                }
                unreachable!();
            }
            Ok(())
        },
    )
    .unwrap();
    panic!("crash cut not reached");
}
#[test]
fn journal9_sigkill_initialization_cuts_never_release_an_owner() {
    use std::os::unix::process::ExitStatusExt;
    let reference_dir = directory();
    let f = actual_fixture(&reference_dir.path().join("chain"));
    for cut in 0..3 {
        let dir = directory();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "journal9_initialization_crash_child",
                "--nocapture",
            ])
            .env(CHILD_DIR, dir.path())
            .env(CHILD_CUT, cut.to_string())
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let raw = std::fs::read(dir.path().join("independent-cut")).unwrap();
        assert_eq!(raw.len(), 136);
        let pin = EpochSafetyHeadPinV1 {
            journal_id: raw[..32].try_into().unwrap(),
            revision: u64::from_le_bytes(raw[32..40].try_into().unwrap()),
            chain_checksum: raw[40..72].try_into().unwrap(),
        };
        let h = f.checkpoint.header();
        let artifact = ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(h.id(), h.parent_id(), raw[72..104].try_into().unwrap()),
            raw[104..136].try_into().unwrap(),
        );
        let profile = profile_for_artifact(&f, artifact);
        let opened = SqliteEpochSafetyJournalV1::open_existing_v1(
            dir.path().join("epoch9.db"),
            profile,
            pin,
        );
        if cut == 0 {
            assert!(opened.is_err());
        } else {
            let store = opened.unwrap();
            let (head, inert) = store.prepare_recovery_v1(pin).unwrap();
            assert_eq!(head.revision_v1(), pin.revision);
            assert_eq!(inert.state().current_view().get(), 1);
            assert_eq!(inert.state().application_applied().height().get(), 8);
            // Both return types are inert: no StorageAck/step/signer lease API.
        }
    }
}
