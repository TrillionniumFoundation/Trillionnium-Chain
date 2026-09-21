#![cfg(all(target_os = "linux", feature = "test-fixtures"))]

use ed25519_dalek::{Signer, SigningKey};
use std::{
    ffi::OsString,
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use trnm_consensus_core::*;
use trnm_consensus_crypto::*;
use trnm_consensus_safety_store::{test_fixtures::*, *};
use trnm_consensus_types::*;

fn directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

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

fn activation(fixture: &NativeOldEpochTerminalFixtureV1) -> StrictEpochRuntimeContextV1 {
    let prepared = fixture
        .application
        .confirm_prepared_checkpoint_execution_v1(
            &fixture.checkpoint,
            &fixture.checkpoint_execution,
        )
        .unwrap();
    let proof = decode_finality_proof_v0_exact(
        &fixture.checkpoint_finality_bytes,
        prepared.old_validator_set(),
        prepared.old_parameters(),
        7000,
    )
    .unwrap();
    let anchor = decode_epoch_anchor_authorization_kernel_v0_exact(
        &fixture.handoff_anchor_bytes,
        prepared.old_validator_set(),
        prepared.new_validator_set(),
    )
    .unwrap();
    let strict = verify_same_version_epoch_activation_authority_strict_v0(
        &proof,
        &prepared.next_epoch_commitment(),
        &anchor,
        prepared.old_validator_set(),
        prepared.old_parameters(),
        prepared.new_validator_set(),
        prepared.new_parameters(),
        &fixture.checkpoint_parent_header,
    )
    .unwrap();
    StrictEpochRuntimeContextV1::from_activation_v1(strict).unwrap()
}

fn with_context<T>(
    fixture: &NativeOldEpochTerminalFixtureV1,
    artifact_override: Option<ValidatedPayloadArtifactRefV0>,
    action: impl FnOnce(&EpochSafetyStateRecordContextV2<'_>) -> T,
) -> T {
    let runtime = Box::new(activation(fixture));
    let activation = runtime.activation();
    let binding = *activation.binding_ref().as_bytes();
    let entry = EpochPreparationEntryV2 {
        binding_ref: binding,
        retained_ancestry: &[],
        evidence: runtime.evidence_bytes().as_preimages(),
    };
    let preparation = prepare_epoch_handoff_evidence_v2(
        &[entry],
        activation.old_validator_set(),
        activation.old_consensus_parameters(),
        binding,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(preparation.record_v2().entry_count_v2(), 1);
    let config = CoreConfig::new(
        activation.new_validator_set().validators()[0].id(),
        activation.new_validator_set().clone(),
        *activation.new_consensus_parameters(),
        0,
        32,
        64,
    )
    .unwrap();
    let native = fixture
        .application
        .confirm_durable_execution_history_row_v0(&fixture.checkpoint_execution)
        .unwrap();
    let header = fixture.checkpoint.header();
    let artifact = artifact_override.unwrap_or_else(|| {
        ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(header.id(), header.parent_id(), native.overlay_digest_v0()),
            native.artifact_digest_v0(),
        )
    });
    let limits = minimum_epoch_safety_record_limits_v2(&config, &preparation).unwrap();
    let context = EpochSafetyStateRecordContextV2::new(
        &config,
        preparation,
        artifact,
        fixture.profile.owner_generation_v1() + 1,
        limits,
    )
    .unwrap();
    action(&context)
}

fn prepare(
    fixture: &NativeOldEpochTerminalFixtureV1,
) -> (
    EpochSafetyJournalProfileV2,
    Box<PreparedEpochCoreActivationV2>,
) {
    with_context(fixture, None, |context| {
        let profile =
            EpochSafetyJournalProfileV2::from_journal8_v2(&fixture.profile, context).unwrap();
        let (_, recovered) = fixture
            .journal
            .prepare_terminal_recovery_v1(fixture.pin)
            .unwrap();
        (
            profile,
            Box::new(recovered.prepare_epoch_activation_v2(context).unwrap()),
        )
    })
}

fn profile_for_artifact(
    fixture: &NativeOldEpochTerminalFixtureV1,
    artifact: ValidatedPayloadArtifactRefV0,
) -> EpochSafetyJournalProfileV2 {
    with_context(fixture, Some(artifact), |context| {
        EpochSafetyJournalProfileV2::from_journal8_v2(&fixture.profile, context).unwrap()
    })
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path);
    name.push(suffix);
    PathBuf::from(name)
}

fn assert_no_namespace(path: &Path) {
    for suffix in ["", ".epoch.lock", "-wal", "-shm", "-journal"] {
        assert!(
            !sidecar(path, suffix).exists(),
            "unexpected namespace file {suffix}"
        );
    }
}

fn durable_image(path: &Path) -> Vec<Vec<u8>> {
    // SHM carries transient SQLite reader slots, not durable authority bytes.
    ["", "-wal", ".epoch.lock"]
        .iter()
        .map(|suffix| std::fs::read(sidecar(path, suffix)).unwrap())
        .collect()
}

fn copy_namespace(source: &Path, target: &Path) {
    for suffix in ["", ".epoch.lock", "-wal", "-shm"] {
        std::fs::copy(sidecar(source, suffix), sidecar(target, suffix)).unwrap();
        std::fs::set_permissions(
            sidecar(target, suffix),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
}

fn mutate(path: &Path, sql: &str) {
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut persist = 1i32;
    // Keep sidecars so a corruption rejection cannot be explained by SQLite
    // deleting the namespace when this explicit test mutation handle closes.
    assert_eq!(
        unsafe {
            rusqlite::ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
                (&mut persist as *mut i32).cast(),
            )
        },
        rusqlite::ffi::SQLITE_OK
    );
    connection.execute_batch(sql).unwrap();
    connection.close().unwrap();
}

#[test]
fn journal10_actual_source8_migration_retry_affinity_cold_recovery_and_corruption() {
    let dir = directory();
    let fixture = actual_fixture(&dir.path().join("chain"));
    run_migration_checks(dir.path(), fixture);
}

fn run_migration_checks(dir: &Path, fixture: Box<NativeOldEpochTerminalFixtureV1>) {
    let (profile, prepared) = prepare(&fixture);
    let (same_profile, foreign) = prepare(&fixture);
    assert_eq!(profile.profile_ref_v2(), same_profile.profile_ref_v2());
    assert_eq!(prepared.state(), foreign.state());
    assert!(!prepared
        .persistence_binding_v2()
        .accepts(foreign.initial_persistence_v2()));
    let source = fixture.journal.fresh_read_v1(fixture.pin).unwrap();
    let path = dir.join("epoch10.db");
    let stale_source = OldEpochSafetyHeadPinV1 {
        revision: fixture.pin.revision - 1,
        ..fixture.pin
    };
    assert!(SqliteEpochSafetyJournalV2::initialize_from_source_v2(
        &path,
        profile.clone(),
        EpochSafetySourceOwnerV2::Journal8(&fixture.journal, stale_source),
        &prepared,
    )
    .is_err());
    assert_no_namespace(&path);

    let original_artifact = prepared
        .state()
        .epoch_state_v1()
        .unwrap()
        .checkpoint_artifact();
    let changed_artifact =
        ValidatedPayloadArtifactRefV0::new(original_artifact.overlay(), [0xa7; 32]);
    let wrong_profile = profile_for_artifact(&fixture, changed_artifact);
    assert!(matches!(
        SqliteEpochSafetyJournalV2::initialize_from_source_v2(
            &path,
            wrong_profile.clone(),
            EpochSafetySourceOwnerV2::Journal8(&fixture.journal, fixture.pin),
            &prepared,
        ),
        Err(EpochJournalErrorV2::Invalid(
            "activation request differs from exact terminal successor"
        ))
    ));
    assert_no_namespace(&path);

    let (mut journal, head) = SqliteEpochSafetyJournalV2::initialize_from_source_v2(
        &path,
        profile.clone(),
        EpochSafetySourceOwnerV2::Journal8(&fixture.journal, fixture.pin),
        &prepared,
    )
    .unwrap();
    let pin = head.pin_v2();
    assert_eq!(head.state_v2(), prepared.state());
    assert_eq!(head.revision_v2(), fixture.pin.revision + 1);
    assert_eq!(head.owner_generation_v2(), 2);
    assert_eq!(head.state_v2().current_view().get(), 1);
    assert_eq!(head.state_v2().application_applied().height().get(), 8);
    assert_eq!(
        head.state_v2().application_applied(),
        head.state_v2().finalized()
    );
    assert!(head.state_v2().pending_sign().is_none());
    assert_eq!(
        head.state_v2()
            .epoch_state_v1()
            .unwrap()
            .checkpoint_artifact(),
        original_artifact
    );
    assert!(head.belongs_to_store_at_path_v2(&journal, &path));
    let origin = head.migration_source_v2();
    assert_eq!(
        origin.pin_v2(),
        EpochSafetySourcePinV2 {
            kind: EpochSafetySourceKindV2::Journal8,
            journal_id: fixture.pin.journal_id,
            revision: fixture.pin.revision,
            chain_checksum: fixture.pin.chain_checksum,
        }
    );
    assert_eq!(
        origin.state_record_checksum_v2(),
        source.state_record_checksum_v1()
    );
    assert_eq!(origin.context_ref_v2(), source.context_ref_v1());
    assert_eq!(origin.profile_ref_v2(), fixture.profile.profile_ref_v1());
    assert_eq!(origin.initial_revision_v2(), pin.revision);
    let ordinary = SafetyTransitionContextV0::ordinary();
    assert_eq!(
        journal
            .confirm_exact_request_v2(pin, prepared.initial_persistence_v2(), &ordinary)
            .unwrap()
            .pin_v2(),
        pin
    );
    assert_eq!(
        journal
            .persist_exact_v2(pin, prepared.initial_persistence_v2(), &ordinary)
            .unwrap()
            .pin_v2(),
        pin
    );
    assert!(matches!(
        journal.persist_exact_v2(pin, foreign.initial_persistence_v2(), &ordinary),
        Err(EpochJournalErrorV2::Invalid(
            "journal is not bound to this live Core"
        ))
    ));
    assert!(matches!(
        journal.confirm_exact_request_v2(pin, foreign.initial_persistence_v2(), &ordinary),
        Err(EpochJournalErrorV2::Invalid(
            "exact confirmation requires this journal's bound Core request"
        ))
    ));
    // Rejecting an unrelated request does not fence the real owner's exact retry.
    assert_eq!(
        journal
            .persist_exact_v2(pin, prepared.initial_persistence_v2(), &ordinary)
            .unwrap()
            .pin_v2(),
        pin
    );

    let other_path = dir.join("other10.db");
    let (other, other_head) = SqliteEpochSafetyJournalV2::initialize_from_source_v2(
        &other_path,
        same_profile,
        EpochSafetySourceOwnerV2::Journal8(&fixture.journal, fixture.pin),
        &foreign,
    )
    .unwrap();
    assert_ne!(pin.journal_id, other_head.journal_id_v2());
    assert!(!head.belongs_to_store_at_path_v2(&other, &other_path));
    assert!(!other_head.belongs_to_store_at_path_v2(&journal, &path));
    drop(other);
    assert_eq!(
        fixture
            .journal
            .fresh_read_v1(fixture.pin)
            .unwrap()
            .state_v1(),
        source.state_v1()
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
    drop(journal);
    drop(fixture);
    // Cold target recovery uses its immutable immediate-source record/profile,
    // and must not recursively open the historical source namespace.
    std::fs::rename(dir.join("chain"), dir.join("retired-chain")).unwrap();
    let before = durable_image(&path);
    assert!(matches!(
        SqliteEpochSafetyJournalV2::open_existing_v2(&path, wrong_profile, pin),
        Err(EpochJournalErrorV2::Invalid("lock binding"))
    ));
    assert_eq!(durable_image(&path), before);
    let mut reopened =
        SqliteEpochSafetyJournalV2::open_existing_v2(&path, profile.clone(), pin).unwrap();
    assert!(!head.belongs_to_store_at_path_v2(&reopened, &path));
    let (fresh, recovery) = reopened.prepare_recovery_v2(pin).unwrap();
    assert_eq!(recovery.state(), prepared.state());
    assert_eq!(recovery.record_checksum(), fresh.state_record_checksum_v2());
    assert_eq!(fresh.migration_source_v2(), head.migration_source_v2());
    assert!(matches!(
        reopened.persist_exact_v2(pin, prepared.initial_persistence_v2(), &ordinary),
        Err(EpochJournalErrorV2::Invalid(
            "journal is not bound to this live Core"
        ))
    ));
    let stale = EpochSafetyHeadPinV2 {
        revision: pin.revision + 1,
        ..pin
    };
    assert!(matches!(
        reopened.fresh_read_v2(stale),
        Err(EpochJournalErrorV2::Invalid(
            "active head differs from independently expected cut"
        ))
    ));
    drop(reopened);

    for (name, sql, reason) in [
        (
            "profile",
            "UPDATE epoch_metadata SET profile=zeroblob(32)",
            "metadata profile/source binding",
        ),
        (
            "origin",
            "UPDATE epoch_metadata SET source_chain=zeroblob(32)",
            "metadata profile/source binding",
        ),
        (
            "source-kind",
            "PRAGMA ignore_check_constraints=ON; UPDATE epoch_metadata SET source_kind=3",
            "metadata profile/source binding",
        ),
        (
            "head",
            "UPDATE epoch_head SET revision=revision+1",
            "active head differs from independently expected cut",
        ),
    ] {
        let clone = dir.join(format!("{name}.db"));
        copy_namespace(&path, &clone);
        mutate(&clone, sql);
        let before = durable_image(&clone);
        assert!(
            matches!(SqliteEpochSafetyJournalV2::open_existing_v2(&clone, profile.clone(), pin),
            Err(EpochJournalErrorV2::Invalid(actual)) if actual == reason),
            "wrong rejection for {name}"
        );
        assert_eq!(durable_image(&clone), before, "failed open rewrote {name}");
    }
    let missing = dir.join("missing-shm.db");
    copy_namespace(&path, &missing);
    std::fs::remove_file(sidecar(&missing, "-shm")).unwrap();
    let before = durable_image(&missing);
    assert!(matches!(
        SqliteEpochSafetyJournalV2::open_existing_v2(&missing, profile, pin),
        Err(EpochJournalErrorV2::Namespace(
            EpochPreparationStoreErrorV1::Missing(_)
        ))
    ));
    assert!(!sidecar(&missing, "-shm").exists());
    assert_eq!(durable_image(&missing), before);
}

const CHILD_DIR: &str = "TRNM_JOURNAL10_CHILD_DIR";
const CHILD_CUT: &str = "TRNM_JOURNAL10_CHILD_CUT";

#[test]
#[ignore = "dedicated process-death child, invoked by journal10_sigkill_initialization_cuts"]
fn journal10_initialization_crash_child() {
    let path =
        PathBuf::from(std::env::var_os(CHILD_DIR).expect("parent supplies private child path"));
    let cut: usize = std::env::var(CHILD_CUT).unwrap().parse().unwrap();
    let fixture = actual_fixture(&path.join("chain"));
    run_crash_child(&path, cut, &fixture);
}

fn run_crash_child(path: &Path, cut: usize, fixture: &NativeOldEpochTerminalFixtureV1) {
    let (profile, prepared) = prepare(fixture);
    let artifact = prepared
        .state()
        .epoch_state_v1()
        .unwrap()
        .checkpoint_artifact();
    SqliteEpochSafetyJournalV2::initialize_with_observer_v2(
        path.join("epoch10.db"),
        profile,
        EpochSafetySourceOwnerV2::Journal8(&fixture.journal, fixture.pin),
        &prepared,
        |at, pin| {
            let index = match at {
                EpochJournalCutV2::AfterWriteBeforeCommit => 0,
                EpochJournalCutV2::AfterCommitBeforeSync => 1,
                EpochJournalCutV2::AfterSyncBeforeReadback => 2,
            };
            if index == cut {
                use std::io::Write;
                // The parent retains a test-owned comparison pin, never a
                // caller-constructible receipt or permission to run Core.
                let mut bytes = Vec::new();
                bytes.extend(pin.journal_id);
                bytes.extend(pin.revision.to_le_bytes());
                bytes.extend(pin.chain_checksum);
                bytes.extend(artifact.overlay().overlay_checksum());
                bytes.extend(artifact.source_artifact_checksum());
                let mut file = std::fs::File::create(path.join("independent-cut")).unwrap();
                file.write_all(&bytes).unwrap();
                file.sync_all().unwrap();
                std::fs::File::open(path).unwrap().sync_all().unwrap();
                unsafe {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                }
                unreachable!();
            }
            Ok(())
        },
    )
    .unwrap();
    std::fs::write(path.join("returned-owner"), b"unexpected").unwrap();
    panic!("crash cut was not reached");
}

#[test]
fn journal10_sigkill_initialization_cuts_never_release_an_owner() {
    let reference = directory();
    let fixture = actual_fixture(&reference.path().join("chain"));
    run_crash_parent(&fixture);
}

fn run_crash_parent(fixture: &NativeOldEpochTerminalFixtureV1) {
    for cut in 0..3 {
        let dir = directory();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "journal10_initialization_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD_DIR, dir.path())
            .env(CHILD_CUT, cut.to_string())
            .env_remove("RUST_MIN_STACK")
            .env_remove("RUST_LOG")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(90);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("journal10 crash child {cut} exceeded 90 seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(!dir.path().join("returned-owner").exists());
        let bytes = std::fs::read(dir.path().join("independent-cut")).unwrap();
        assert_eq!(bytes.len(), 136);
        let pin = EpochSafetyHeadPinV2 {
            journal_id: bytes[..32].try_into().unwrap(),
            revision: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            chain_checksum: bytes[40..72].try_into().unwrap(),
        };
        let header = fixture.checkpoint.header();
        let artifact = ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(
                header.id(),
                header.parent_id(),
                bytes[72..104].try_into().unwrap(),
            ),
            bytes[104..136].try_into().unwrap(),
        );
        // Each actual child has its own native artifact IDs. Reuse only the
        // deterministic trusted configuration/evidence, retaining those IDs.
        let profile = profile_for_artifact(fixture, artifact);
        let opened = SqliteEpochSafetyJournalV2::open_existing_v2(
            dir.path().join("epoch10.db"),
            profile,
            pin,
        );
        if cut == 0 {
            assert!(opened.is_err());
        } else {
            let journal = opened.unwrap();
            let (head, recovery) = journal.prepare_recovery_v2(pin).unwrap();
            assert_eq!(head.pin_v2(), pin);
            assert_eq!(recovery.record_checksum(), head.state_record_checksum_v2());
            assert_eq!(recovery.state().current_view().get(), 1);
            assert_eq!(recovery.state().application_applied().height().get(), 8);
            assert!(recovery.state().pending_sign().is_none());
            assert_eq!(
                recovery
                    .state()
                    .epoch_state_v1()
                    .unwrap()
                    .checkpoint_artifact(),
                artifact
            );
        }
    }
}

#[cfg(feature = "candidate-epoch-host-v2")]
#[test]
fn journal10_initial_recovery_binds_fresh_owner_before_real_timeout_persistence() {
    let dir = directory();
    let fixture = actual_fixture(&dir.path().join("chain"));
    run_initial_recovery_checks(dir.path(), &fixture);
}

#[cfg(feature = "candidate-epoch-host-v2")]
fn run_initial_recovery_checks(dir: &Path, fixture: &NativeOldEpochTerminalFixtureV1) {
    let (profile, prepared) = prepare(fixture);
    let path = dir.join("initial-host10.db");
    let (mut original, original_head) = SqliteEpochSafetyJournalV2::initialize_from_source_v2(
        &path,
        profile.clone(),
        EpochSafetySourceOwnerV2::Journal8(&fixture.journal, fixture.pin),
        &prepared,
    )
    .unwrap();
    let pin = original_head.pin_v2();
    assert!(matches!(
        original.prepare_candidate_host_initial_recovery_v2(pin),
        Err(EpochJournalErrorV2::Invalid(
            "journal already bound; recovery cannot duplicate a live driver"
        ))
    ));
    let old_request = prepared.initial_persistence_v2().clone();
    let ordinary = SafetyTransitionContextV0::ordinary();
    original
        .confirm_exact_request_v2(pin, &old_request, &ordinary)
        .unwrap();
    drop(original);
    drop(prepared);

    let mut journal =
        SqliteEpochSafetyJournalV2::open_existing_v2(&path, profile.clone(), pin).unwrap();
    assert!(matches!(
        journal.confirm_exact_request_v2(pin, &old_request, &ordinary),
        Err(EpochJournalErrorV2::Invalid(
            "exact confirmation requires this journal's bound Core request"
        ))
    ));
    assert!(matches!(
        journal.prepare_candidate_host_initial_recovery_v2(EpochSafetyHeadPinV2 {
            revision: pin.revision + 1,
            ..pin
        }),
        Err(EpochJournalErrorV2::Invalid(
            "active head differs from independently expected cut"
        ))
    ));

    // A separately recovered, equally valid initial state carries a different
    // affinity. It must not become a second journal-bound Core owner.
    let (_, foreign_recovery) = journal.prepare_recovery_v2(pin).unwrap();
    let foreign_driver = foreign_recovery
        .into_candidate_host_initial_pending_v2()
        .unwrap();
    let (fresh, mut driver) = journal
        .prepare_candidate_host_initial_recovery_v2(pin)
        .unwrap();
    assert!(fresh.belongs_to_store_at_path_v2(&journal, &path));
    assert!(!original_head.belongs_to_store_at_path_v2(&journal, &path));
    assert_eq!(driver.state(), fresh.state_v2());
    assert_eq!(driver.state(), foreign_driver.state());
    assert_eq!(fresh.pin_v2(), pin);
    assert!(driver.activation_persistence_pending_v2());
    assert!(!driver.persistence_binding_v2().accepts(&old_request));
    assert!(!driver
        .persistence_binding_v2()
        .accepts(foreign_driver.initial_persistence_v2()));
    assert!(matches!(
        journal.confirm_exact_request_v2(pin, foreign_driver.initial_persistence_v2(), &ordinary),
        Err(EpochJournalErrorV2::Invalid(
            "exact confirmation requires this journal's bound Core request"
        ))
    ));
    assert!(matches!(
        journal.confirm_exact_request_v2(pin, &old_request, &ordinary),
        Err(EpochJournalErrorV2::Invalid(
            "exact confirmation requires this journal's bound Core request"
        ))
    ));
    assert!(matches!(
        journal.prepare_candidate_host_initial_recovery_v2(pin),
        Err(EpochJournalErrorV2::Invalid(
            "journal already bound; recovery cannot duplicate a live driver"
        ))
    ));
    journal
        .confirm_exact_request_v2(pin, driver.initial_persistence_v2(), &ordinary)
        .unwrap();
    assert!(matches!(
        driver.step_v2(Input::Resume),
        Err(CoreError::EpochActivationPersistencePending)
    ));
    assert!(matches!(
        driver.step_v2(Input::LocalTimeout {
            epoch: Epoch::new(1),
            view: View::new(1)
        }),
        Err(CoreError::EpochActivationPersistencePending)
    ));
    assert!(matches!(
        driver.issue_application_seal_authority_v2(),
        Err(CoreError::EpochActivationPersistencePending)
    ));
    assert!(matches!(
        driver.step_v2(Input::StorageAck {
            barrier: BarrierId::new(pin.revision + 1)
        }),
        Err(CoreError::UnexpectedStorageAck)
    ));
    assert!(driver.activation_persistence_pending_v2());
    assert_eq!(driver.state().revision(), pin.revision);

    // This is an explicit test-only trusted-host ACK. It does not attest a
    // production M15 native/custody/external-watermark activation join.
    assert_eq!(
        driver
            .step_v2(Input::StorageAck {
                barrier: driver.initial_persistence_v2().barrier()
            })
            .unwrap(),
        vec![Effect::ArmViewTimer {
            epoch: Epoch::new(1),
            view: View::new(1)
        }]
    );
    assert!(!driver.activation_persistence_pending_v2());
    let effects = driver
        .step_v2(Input::LocalTimeout {
            epoch: Epoch::new(1),
            view: View::new(1),
        })
        .unwrap();
    let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
        panic!("real timeout must only request durable persistence before signing");
    };
    assert_eq!(request.state().revision(), pin.revision + 1);
    assert!(request.state().pending_sign().is_some());
    assert!(matches!(
        driver.step_v2(Input::Resume),
        Err(CoreError::Busy(
            "waiting for durable safety-state acknowledgement"
        ))
    ));
    let appended = journal.persist_exact_v2(pin, request, &ordinary).unwrap();
    let next = appended.pin_v2();
    assert_eq!(next.revision, pin.revision + 1);
    assert_eq!(appended.state_v2(), request.state());
    let confirmed = journal
        .confirm_exact_request_v2(next, request, &ordinary)
        .unwrap();
    assert_eq!(
        confirmed.state_record_checksum_v2(),
        appended.state_record_checksum_v2()
    );
    assert!(!fresh.belongs_to_store_at_path_v2(&journal, &path));
    assert_eq!(
        journal
            .persist_exact_v2(next, request, &ordinary)
            .unwrap()
            .pin_v2(),
        next
    );
    assert!(matches!(
        driver
            .step_v2(Input::StorageAck {
                barrier: request.barrier()
            })
            .unwrap()
            .as_slice(),
        [Effect::RequestSignature { .. }]
    ));
    // No signature is fabricated or released by this persistence test.
    drop(driver);
    drop(journal);
    let mut progressed =
        SqliteEpochSafetyJournalV2::open_existing_v2(&path, profile, next).unwrap();
    assert!(matches!(
        progressed.prepare_candidate_host_initial_recovery_v2(next),
        Err(EpochJournalErrorV2::Invalid(
            "candidate epoch recovery supports only the exact initial cut"
        ))
    ));
    let (retained, recovery) = progressed.prepare_recovery_v2(next).unwrap();
    assert_eq!(retained.state_v2(), request.state());
    assert!(retained.state_v2().pending_sign().is_some());
    assert!(matches!(
        recovery.into_candidate_host_initial_pending_v2(),
        Err(CoreError::InvalidRecovery(
            "codec2 candidate initial recovery rejects progressed or pending-outbox state"
        ))
    ));
    assert!(matches!(
        progressed.confirm_exact_request_v2(next, request, &ordinary),
        Err(EpochJournalErrorV2::Invalid(
            "exact confirmation requires this journal's bound Core request"
        ))
    ));
}

#[cfg(feature = "candidate-epoch-host-v2")]
#[test]
#[ignore = "dedicated process-death child, invoked by journal10_sigkill_post_initial_cuts"]
fn journal10_post_initial_crash_child() {
    let path =
        PathBuf::from(std::env::var_os(CHILD_DIR).expect("parent supplies private child path"));
    let cut: usize = std::env::var(CHILD_CUT).unwrap().parse().unwrap();
    let fixture = actual_fixture(&path.join("chain"));
    run_post_initial_crash_child(&path, cut, &fixture);
}

#[cfg(feature = "candidate-epoch-host-v2")]
fn run_post_initial_crash_child(
    path: &Path,
    cut: usize,
    fixture: &NativeOldEpochTerminalFixtureV1,
) {
    let (profile, prepared) = prepare(fixture);
    let artifact = prepared
        .state()
        .epoch_state_v1()
        .unwrap()
        .checkpoint_artifact();
    let db = path.join("epoch10.db");
    let (original, initial) = SqliteEpochSafetyJournalV2::initialize_from_source_v2(
        &db,
        profile.clone(),
        EpochSafetySourceOwnerV2::Journal8(&fixture.journal, fixture.pin),
        &prepared,
    )
    .unwrap();
    let initial_pin = initial.pin_v2();
    drop(original);
    drop(prepared);
    let mut journal =
        SqliteEpochSafetyJournalV2::open_existing_v2(&db, profile, initial_pin).unwrap();
    let (_, mut driver) = journal
        .prepare_candidate_host_initial_recovery_v2(initial_pin)
        .unwrap();
    journal
        .confirm_exact_request_v2(
            initial_pin,
            driver.initial_persistence_v2(),
            &SafetyTransitionContextV0::ordinary(),
        )
        .unwrap();
    // Test-only host ACK exercises the persisted timeout boundary; no claim of
    // physical M15 custody/native commissioning is made by this harness.
    assert!(matches!(
        driver
            .step_v2(Input::StorageAck {
                barrier: driver.initial_persistence_v2().barrier()
            })
            .unwrap()
            .as_slice(),
        [Effect::ArmViewTimer { .. }]
    ));
    let effects = driver
        .step_v2(Input::LocalTimeout {
            epoch: Epoch::new(1),
            view: View::new(1),
        })
        .unwrap();
    let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
        panic!("timeout persistence required");
    };
    journal
        .persist_with_pin_observer_v2(
            initial_pin,
            request,
            &SafetyTransitionContextV0::ordinary(),
            |at, next_pin| {
                let index = match at {
                    EpochJournalCutV2::AfterWriteBeforeCommit => 0,
                    EpochJournalCutV2::AfterCommitBeforeSync => 1,
                    EpochJournalCutV2::AfterSyncBeforeReadback => 2,
                };
                if index == cut {
                    use std::io::Write;
                    assert_eq!(next_pin.journal_id, initial_pin.journal_id);
                    assert_eq!(next_pin.revision, initial_pin.revision + 1);
                    let mut bytes = Vec::new();
                    for pin in [initial_pin, next_pin] {
                        bytes.extend(pin.journal_id);
                        bytes.extend(pin.revision.to_le_bytes());
                        bytes.extend(pin.chain_checksum);
                    }
                    bytes.extend(artifact.overlay().overlay_checksum());
                    bytes.extend(artifact.source_artifact_checksum());
                    let mut file =
                        std::fs::File::create(path.join("independent-post-initial-cut")).unwrap();
                    file.write_all(&bytes).unwrap();
                    file.sync_all().unwrap();
                    std::fs::File::open(path).unwrap().sync_all().unwrap();
                    unsafe {
                        libc::kill(libc::getpid(), libc::SIGKILL);
                    }
                    unreachable!();
                }
                Ok(())
            },
        )
        .unwrap();
    std::fs::write(path.join("returned-timeout-owner"), b"unexpected").unwrap();
    panic!("post-initial crash cut was not reached");
}

#[cfg(feature = "candidate-epoch-host-v2")]
#[test]
fn journal10_sigkill_post_initial_cuts_recover_exact_independently_pinned_revision() {
    let reference = directory();
    let fixture = actual_fixture(&reference.path().join("chain"));
    run_post_initial_crash_parent(&fixture);
}

#[cfg(feature = "candidate-epoch-host-v2")]
fn run_post_initial_crash_parent(fixture: &NativeOldEpochTerminalFixtureV1) {
    for cut in 0..3 {
        let dir = directory();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "journal10_post_initial_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD_DIR, dir.path())
            .env(CHILD_CUT, cut.to_string())
            .env_remove("RUST_MIN_STACK")
            .env_remove("RUST_LOG")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(90);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("journal10 post-initial child {cut} exceeded 90 seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(!dir.path().join("returned-timeout-owner").exists());
        let bytes = std::fs::read(dir.path().join("independent-post-initial-cut")).unwrap();
        assert_eq!(bytes.len(), 208);
        let parse_pin = |bytes: &[u8]| EpochSafetyHeadPinV2 {
            journal_id: bytes[..32].try_into().unwrap(),
            revision: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            chain_checksum: bytes[40..72].try_into().unwrap(),
        };
        let initial_pin = parse_pin(&bytes[..72]);
        let next_pin = parse_pin(&bytes[72..144]);
        let header = fixture.checkpoint.header();
        let artifact = ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(
                header.id(),
                header.parent_id(),
                bytes[144..176].try_into().unwrap(),
            ),
            bytes[176..208].try_into().unwrap(),
        );
        let profile = profile_for_artifact(fixture, artifact);
        let db = dir.path().join("epoch10.db");
        let (expected, rejected) = if cut == 0 {
            (initial_pin, next_pin)
        } else {
            (next_pin, initial_pin)
        };
        assert!(
            SqliteEpochSafetyJournalV2::open_existing_v2(&db, profile.clone(), rejected).is_err()
        );
        let mut journal =
            SqliteEpochSafetyJournalV2::open_existing_v2(&db, profile, expected).unwrap();
        let (head, recovery) = journal.prepare_recovery_v2(expected).unwrap();
        assert_eq!(head.pin_v2(), expected);
        assert_eq!(
            head.migration_source_v2().initial_revision_v2(),
            initial_pin.revision
        );
        assert_eq!(recovery.state(), head.state_v2());
        assert_eq!(head.state_v2().pending_sign().is_some(), cut != 0);
        if cut == 0 {
            let (_, driver) = journal
                .prepare_candidate_host_initial_recovery_v2(expected)
                .unwrap();
            assert!(driver.activation_persistence_pending_v2());
        } else {
            assert!(matches!(
                journal.prepare_candidate_host_initial_recovery_v2(expected),
                Err(EpochJournalErrorV2::Invalid(
                    "candidate epoch recovery supports only the exact initial cut"
                ))
            ));
        }
        // One real timeout append retains initial+successor. This test does not
        // claim that the immutable origin was audited after initial-row pruning.
    }
}
