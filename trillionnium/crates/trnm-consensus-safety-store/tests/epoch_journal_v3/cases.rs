// Included in the existing codec2 integration target: one genuine source
// builder, unchanged Journal10 tests, no synthetic settled Safety rows.
fn prepare11(
    fixture: &NativeOldEpochTerminalFixtureV1,
) -> (
    EpochSafetyJournalProfileV3,
    Box<PreparedEpochCoreActivationV2>,
) {
    with_context(fixture, None, |context| {
        let profile =
            EpochSafetyJournalProfileV3::from_journal8_v3(&fixture.profile, context).unwrap();
        let (_, recovery) = fixture
            .journal
            .prepare_terminal_recovery_v1(fixture.pin)
            .unwrap();
        (
            profile,
            Box::new(recovery.prepare_epoch_activation_v2(context).unwrap()),
        )
    })
}
#[cfg(feature = "candidate-epoch-host-v2")]
fn profile11_for_artifact(
    fixture: &NativeOldEpochTerminalFixtureV1,
    artifact: ValidatedPayloadArtifactRefV0,
) -> EpochSafetyJournalProfileV3 {
    with_context(fixture, Some(artifact), |context| {
        EpochSafetyJournalProfileV3::from_journal8_v3(&fixture.profile, context).unwrap()
    })
}
type Journal11StoredImage = (Vec<u8>, Vec<u8>, Vec<(u64, Vec<u8>)>);
fn journal11_blobs(path: &Path) -> Journal11StoredImage {
    let c = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    let prefix: Vec<u8> = c
        .query_row(
            "SELECT provenance FROM epoch_provenance WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        c.query_row("SELECT count(*) FROM epoch_provenance", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    let source = c
        .query_row(
            "SELECT source_record FROM epoch_metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut s = c
        .prepare("SELECT revision,record_before,record_after FROM epoch_records ORDER BY revision")
        .unwrap();
    let rows = s
        .query_map([], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .unwrap()
        .map(|row| {
            let (revision, mut before, after) = row.unwrap();
            before.extend_from_slice(&prefix);
            before.extend(after);
            (revision, before)
        })
        .collect();
    (prefix, source, rows)
}

#[test]
fn journal11_actual_source8_prefix_once_reconstruction_retry_affinity_and_corruption() {
    let dir = directory();
    let fixture = actual_fixture(&dir.path().join("chain"));
    journal11_migration_checks(dir.path(), &fixture);
}
#[inline(never)]
fn journal11_migration_checks(dir: &Path, fixture: &NativeOldEpochTerminalFixtureV1) {
    let (profile, prepared) = prepare11(fixture);
    let (old_profile, foreign) = prepare(fixture);
    assert_ne!(profile.profile_ref_v3(), old_profile.profile_ref_v2());
    assert_eq!(
        profile.context_ref_v3().unwrap(),
        old_profile.context_ref_v2().unwrap()
    );
    let path = dir.join("epoch11.db");
    let stale = OldEpochSafetyHeadPinV1 {
        revision: fixture.pin.revision - 1,
        ..fixture.pin
    };
    assert!(SqliteEpochSafetyJournalV3::initialize_from_source_v3(
        &path,
        profile.clone(),
        EpochSafetySourceOwnerV3::Journal8(&fixture.journal, stale),
        &prepared
    )
    .is_err());
    assert_no_namespace(&path);
    let (mut journal, head) = SqliteEpochSafetyJournalV3::initialize_from_source_v3(
        &path,
        profile.clone(),
        EpochSafetySourceOwnerV3::Journal8(&fixture.journal, fixture.pin),
        &prepared,
    )
    .unwrap();
    let pin = head.pin_v3();
    assert_eq!(head.state_v3(), prepared.state());
    assert!(head.belongs_to_store_at_path_v3(&journal, &path));
    assert_eq!(
        head.migration_source_v3().pin_v2().journal_id,
        fixture.pin.journal_id
    );
    assert!(journal
        .confirm_exact_request_v3(
            pin,
            foreign.initial_persistence_v2(),
            &SafetyTransitionContextV0::ordinary()
        )
        .is_err());
    let original = journal11_blobs(&path);
    let source = rusqlite::Connection::open_with_flags(
        fixture.journal.path_v1(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
    .query_row(
        "SELECT record FROM outgoing_records WHERE revision=?1",
        [fixture.pin.revision],
        |r| r.get::<_, Vec<u8>>(0),
    )
    .unwrap();
    assert_eq!(original.1, source, "retain the original full source record");
    with_context(fixture, None, |context| {
        let parts = encode_epoch_safety_record_parts_v2(prepared.state(), context).unwrap();
        assert_eq!(original.0, parts.provenance());
        assert_eq!(
            original.2,
            vec![(pin.revision, parts.record_bytes().to_vec())]
        );
        assert_eq!(
            decode_epoch_safety_record_v2_exact(&original.2[0].1, context)
                .unwrap()
                .record_checksum(),
            head.state_record_checksum_v3()
        );
    });
    assert_eq!(
        journal
            .persist_exact_v3(
                pin,
                prepared.initial_persistence_v2(),
                &SafetyTransitionContextV0::ordinary()
            )
            .unwrap()
            .pin_v3(),
        pin
    );
    assert_eq!(journal11_blobs(&path), original);
    drop(journal);
    let (cold, recovery) =
        SqliteEpochSafetyJournalV3::open_existing_v3(&path, profile.clone(), pin)
            .unwrap()
            .prepare_recovery_v3(pin)
            .unwrap();
    assert_eq!(cold.state_v3(), recovery.state());
    assert_eq!(
        cold.state_record_checksum_v3(),
        head.state_record_checksum_v3()
    );
    assert!(SqliteEpochSafetyJournalV2::open_existing_v2(
        &path,
        old_profile,
        EpochSafetyHeadPinV2 {
            journal_id: pin.journal_id,
            revision: pin.revision,
            chain_checksum: pin.chain_checksum
        }
    )
    .is_err());
    for (name, sql) in [
        ("prefix-missing", "DELETE FROM epoch_provenance"),
        (
            "prefix-changed",
            "UPDATE epoch_provenance SET provenance=zeroblob(length(provenance))",
        ),
        (
            "prefix-extra",
            "PRAGMA ignore_check_constraints=ON; INSERT INTO epoch_provenance VALUES(2,x'01')",
        ),
        (
            "prefix-reference",
            "PRAGMA ignore_check_constraints=ON; UPDATE epoch_records SET provenance_id=2",
        ),
        (
            "before-truncated",
            "UPDATE epoch_records SET record_before=substr(record_before,2)",
        ),
        (
            "after-checksum",
            "UPDATE epoch_records SET record_after=zeroblob(length(record_after))",
        ),
        (
            "source-record",
            "UPDATE epoch_metadata SET source_record=zeroblob(length(source_record))",
        ),
        ("extra-table", "CREATE TABLE forbidden(x INTEGER) STRICT"),
        ("old-version", "PRAGMA user_version=10"),
    ] {
        let copy = dir.join(format!("journal11-{name}.db"));
        copy_namespace(&path, &copy);
        mutate(&copy, sql);
        let before = durable_image(&copy);
        assert!(
            SqliteEpochSafetyJournalV3::open_existing_v3(&copy, profile.clone(), pin).is_err(),
            "{name}"
        );
        assert_eq!(
            before,
            durable_image(&copy),
            "cold refusal must not rewrite {name}"
        );
    }
    // Relocate one byte out of the shared provenance into the row prefix.
    // Logical codec2 bytes, its original checksum and outer chain are identical;
    // physical split/provenance identity must nevertheless remain exact.
    let relocated = dir.join("journal11-relocated-boundary.db");
    copy_namespace(&path, &relocated);
    mutate(&relocated, "UPDATE epoch_records SET record_before=CAST(record_before || (SELECT substr(provenance,1,1) FROM epoch_provenance) AS BLOB); UPDATE epoch_provenance SET provenance=substr(provenance,2)");
    let relocated_image = journal11_blobs(&relocated);
    assert_eq!(relocated_image.1, original.1);
    assert_eq!(relocated_image.2, original.2);
    assert!(
        SqliteEpochSafetyJournalV3::open_existing_v3(&relocated, profile.clone(), pin).is_err()
    );
    // A physical attacker may recompute the outer chain and supply its new pin.
    // This still cannot replace the independently pinned full preparation.
    let forged = dir.join("journal11-rehashed-prefix.db");
    copy_namespace(&path, &forged);
    journal11_rehash_changed_prefix(&forged, pin, &profile);
}
fn journal11_rehash_changed_prefix(
    path: &Path,
    pin: EpochSafetyHeadPinV3,
    profile: &EpochSafetyJournalProfileV3,
) {
    use sha2::{Digest, Sha256};
    mutate(
        path,
        "UPDATE epoch_provenance SET provenance=zeroblob(length(provenance))",
    );
    let record = journal11_blobs(path).2.remove(0).1;
    let c = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    let (origin, predecessor, transition): (Vec<u8>,Vec<u8>,Vec<u8>) = c.query_row("SELECT m.origin,r.predecessor,r.transition FROM epoch_metadata m JOIN epoch_records r ON r.revision=?1", [pin.revision], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    let mut hash = Sha256::new();
    hash.update(b"trnm.journal11.epoch.chain.v3");
    for part in [
        &origin[..],
        &predecessor,
        &pin.revision.to_be_bytes(),
        &record,
        &transition,
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    let chain: [u8; 32] = hash.finalize().into();
    drop(c);
    let hex: String = chain.iter().map(|byte| format!("{byte:02x}")).collect();
    mutate(
        path,
        &format!("UPDATE epoch_records SET chain=x'{hex}'; UPDATE epoch_head SET chain=x'{hex}'"),
    );
    let error = match SqliteEpochSafetyJournalV3::open_existing_v3(
        path,
        profile.clone(),
        EpochSafetyHeadPinV3 {
            chain_checksum: chain,
            ..pin
        },
    ) {
        Ok(_) => panic!("forged prefix accepted"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("provenance differs from independent context"),
        "{error}"
    );
}

#[cfg(feature = "candidate-epoch-host-v2")]
#[test]
fn journal11_real_timeout_and_signature_release_prune_records_not_provenance() {
    let dir = directory();
    let fixture = actual_fixture(&dir.path().join("chain"));
    journal11_pruning_checks(dir.path(), &fixture);
}
#[cfg(feature = "candidate-epoch-host-v2")]
#[inline(never)]
fn journal11_pruning_checks(dir: &Path, fixture: &NativeOldEpochTerminalFixtureV1) {
    let (profile, prepared) = prepare11(fixture);
    let path = dir.join("epoch11.db");
    let (original, initial) = SqliteEpochSafetyJournalV3::initialize_from_source_v3(
        &path,
        profile.clone(),
        EpochSafetySourceOwnerV3::Journal8(&fixture.journal, fixture.pin),
        &prepared,
    )
    .unwrap();
    let initial_pin = initial.pin_v3();
    let baseline = journal11_blobs(&path);
    drop(original);
    drop(prepared);
    let mut journal =
        SqliteEpochSafetyJournalV3::open_existing_v3(&path, profile.clone(), initial_pin).unwrap();
    let (_, mut driver) = journal
        .prepare_candidate_host_initial_recovery_v3(initial_pin)
        .unwrap();
    assert!(driver
        .step_v2(Input::LocalTimeout {
            epoch: Epoch::new(1),
            view: View::new(1)
        })
        .is_err());
    journal
        .confirm_exact_request_v3(
            initial_pin,
            driver.initial_persistence_v2(),
            &SafetyTransitionContextV0::ordinary(),
        )
        .unwrap();
    driver
        .step_v2(Input::StorageAck {
            barrier: driver.initial_persistence_v2().barrier(),
        })
        .unwrap(); // explicit fixture-only host ACK
    let effects = driver
        .step_v2(Input::LocalTimeout {
            epoch: Epoch::new(1),
            view: View::new(1),
        })
        .unwrap();
    let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
        panic!("timeout must persist first")
    };
    let pending = journal
        .persist_exact_v3(initial_pin, request, &SafetyTransitionContextV0::ordinary())
        .unwrap();
    let pin = pending.pin_v3();
    let effects = driver
        .step_v2(Input::StorageAck {
            barrier: request.barrier(),
        })
        .unwrap();
    let [Effect::RequestSignature { intent }] = effects.as_slice() else {
        panic!("only persisted timeout may request signature")
    };
    let before_release = Box::new(driver.state().clone());
    let key = SigningKey::from_bytes(&[20; 32]);
    let signature =
        SignatureBytes::from_array(key.sign(intent.signing_root().as_bytes()).to_bytes());
    let broadcasts = driver
        .step_v2(Input::SignatureReady {
            id: SignId::new(intent.signing_root()),
            signature,
        })
        .unwrap();
    assert!(broadcasts
        .iter()
        .all(|effect| matches!(effect, Effect::Broadcast(_))));
    let effects = driver
        .persist_signature_release_v2(&before_release)
        .unwrap();
    let [Effect::PersistSafetyState(release)] = effects.as_slice() else {
        panic!("release requires its own real Core revision")
    };
    let released = journal
        .persist_exact_v3(pin, release, &SafetyTransitionContextV0::ordinary())
        .unwrap();
    let final_pin = released.pin_v3();
    assert_eq!(final_pin.revision, initial_pin.revision + 2);
    assert_eq!(
        journal
            .persist_exact_v3(final_pin, release, &SafetyTransitionContextV0::ordinary())
            .unwrap()
            .pin_v3(),
        final_pin
    );
    driver
        .step_v2(Input::StorageAck {
            barrier: release.barrier(),
        })
        .unwrap();
    let blobs = journal11_blobs(&path);
    assert_eq!(blobs.0, baseline.0);
    assert_eq!(blobs.1, baseline.1);
    assert_eq!(
        blobs.2.iter().map(|row| row.0).collect::<Vec<_>>(),
        vec![pin.revision, final_pin.revision]
    );
    with_context(fixture, None, |context| {
        for (state, bytes) in [
            (request.state(), &blobs.2[0].1),
            (release.state(), &blobs.2[1].1),
        ] {
            assert_eq!(
                *bytes,
                encode_epoch_safety_record_v2(state, context).unwrap()
            );
        }
    });
    drop(driver);
    drop(journal);
    let mut cold = SqliteEpochSafetyJournalV3::open_existing_v3(&path, profile, final_pin).unwrap();
    let (head, recovery) = cold.prepare_recovery_v3(final_pin).unwrap();
    assert_eq!(head.state_v3(), release.state());
    assert_eq!(recovery.state(), release.state());
    assert!(head.state_v3().pending_sign().is_none());
    assert!(cold
        .prepare_candidate_host_initial_recovery_v3(final_pin)
        .is_err());
    assert!(cold
        .confirm_exact_request_v3(final_pin, release, &SafetyTransitionContextV0::ordinary())
        .is_err());
}

#[cfg(feature = "candidate-epoch-host-v2")]
const CHILD11_DIR: &str = "TRNM_JOURNAL11_CHILD_DIR";
#[cfg(feature = "candidate-epoch-host-v2")]
const CHILD11_CUT: &str = "TRNM_JOURNAL11_CHILD_CUT";
#[cfg(feature = "candidate-epoch-host-v2")]
#[test]
#[ignore = "dedicated child invoked by journal11_six_sigkill_cuts_keep_original_provenance_and_exact_head"]
fn journal11_sigkill_child() {
    let path = PathBuf::from(std::env::var_os(CHILD11_DIR).expect("private owned child directory"));
    let cut: usize = std::env::var(CHILD11_CUT).unwrap().parse().unwrap();
    let fixture = actual_fixture(&path.join("chain"));
    journal11_crash_child(&path, cut, &fixture);
}
#[cfg(feature = "candidate-epoch-host-v2")]
#[inline(never)]
fn journal11_crash_child(path: &Path, cut: usize, fixture: &NativeOldEpochTerminalFixtureV1) {
    let (profile, prepared) = prepare11(fixture);
    let artifact = prepared
        .state()
        .epoch_state_v1()
        .unwrap()
        .checkpoint_artifact();
    let target = path.join("epoch11.db");
    let (owner, head) = SqliteEpochSafetyJournalV3::initialize_with_observer_v3(
        &target,
        profile.clone(),
        EpochSafetySourceOwnerV3::Journal8(&fixture.journal, fixture.pin),
        &prepared,
        |at, pin| {
            if cut < 3 && journal11_cut_index(at) == cut {
                journal11_die_at_cut(path, &[pin], artifact);
            }
            Ok(())
        },
    )
    .unwrap();
    let initial = head.pin_v3();
    drop(owner);
    drop(prepared);
    let mut journal =
        SqliteEpochSafetyJournalV3::open_existing_v3(&target, profile, initial).unwrap();
    let (_, mut driver) = journal
        .prepare_candidate_host_initial_recovery_v3(initial)
        .unwrap();
    journal
        .confirm_exact_request_v3(
            initial,
            driver.initial_persistence_v2(),
            &SafetyTransitionContextV0::ordinary(),
        )
        .unwrap();
    driver
        .step_v2(Input::StorageAck {
            barrier: driver.initial_persistence_v2().barrier(),
        })
        .unwrap(); // explicit test host ACK only
    let effects = driver
        .step_v2(Input::LocalTimeout {
            epoch: Epoch::new(1),
            view: View::new(1),
        })
        .unwrap();
    let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
        panic!("real timeout must persist before sign")
    };
    journal
        .persist_with_pin_observer_v3(
            initial,
            request,
            &SafetyTransitionContextV0::ordinary(),
            |at, pin| {
                if journal11_cut_index(at) + 3 == cut {
                    journal11_die_at_cut(path, &[initial, pin], artifact);
                }
                Ok(())
            },
        )
        .unwrap();
    std::fs::write(
        path.join("unexpected-return"),
        b"owner returned past selected cut",
    )
    .unwrap();
    panic!("selected SIGKILL cut was not reached");
}
#[cfg(feature = "candidate-epoch-host-v2")]
fn journal11_cut_index(cut: EpochJournalCutV3) -> usize {
    match cut {
        EpochJournalCutV3::AfterWriteBeforeCommit => 0,
        EpochJournalCutV3::AfterCommitBeforeSync => 1,
        EpochJournalCutV3::AfterSyncBeforeReadback => 2,
    }
}
#[cfg(feature = "candidate-epoch-host-v2")]
fn journal11_die_at_cut(
    path: &Path,
    pins: &[EpochSafetyHeadPinV3],
    artifact: ValidatedPayloadArtifactRefV0,
) -> ! {
    use std::io::Write;
    let mut bytes = Vec::new();
    for pin in pins {
        bytes.extend(pin.journal_id);
        bytes.extend(pin.revision.to_le_bytes());
        bytes.extend(pin.chain_checksum);
    }
    bytes.extend(artifact.overlay().overlay_checksum());
    bytes.extend(artifact.source_artifact_checksum());
    let mut marker = std::fs::File::create(path.join("independent11-cut")).unwrap();
    marker.write_all(&bytes).unwrap();
    marker.sync_all().unwrap();
    std::fs::File::open(path).unwrap().sync_all().unwrap();
    unsafe {
        libc::kill(libc::getpid(), libc::SIGKILL);
    }
    panic!("SIGKILL did not terminate child");
}
#[cfg(feature = "candidate-epoch-host-v2")]
#[test]
fn journal11_six_sigkill_cuts_keep_original_provenance_and_exact_head() {
    let reference = directory();
    let fixture = actual_fixture(&reference.path().join("chain"));
    journal11_crash_parent(&fixture);
}
#[cfg(feature = "candidate-epoch-host-v2")]
#[inline(never)]
fn journal11_crash_parent(fixture: &NativeOldEpochTerminalFixtureV1) {
    for cut in 0..6 {
        let dir = directory();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "journal11_sigkill_child",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD11_DIR, dir.path())
            .env(CHILD11_CUT, cut.to_string())
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
                panic!("journal11 child cut {cut} exceeded90 seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "real SIGKILL required for cut {cut}"
        );
        assert!(!dir.path().join("unexpected-return").exists());
        let marker = std::fs::read(dir.path().join("independent11-cut")).unwrap();
        let pin_count = if cut < 3 { 1 } else { 2 };
        assert_eq!(marker.len(), pin_count * 72 + 64);
        let parse = |bytes: &[u8]| EpochSafetyHeadPinV3 {
            journal_id: bytes[..32].try_into().unwrap(),
            revision: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            chain_checksum: bytes[40..72].try_into().unwrap(),
        };
        let first = parse(&marker[..72]);
        let last = parse(&marker[(pin_count - 1) * 72..pin_count * 72]);
        let offset = pin_count * 72;
        let artifact = ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(
                fixture.checkpoint.header().id(),
                fixture.checkpoint.header().parent_id(),
                marker[offset..offset + 32].try_into().unwrap(),
            ),
            marker[offset + 32..offset + 64].try_into().unwrap(),
        );
        let profile = profile11_for_artifact(fixture, artifact);
        let target = dir.path().join("epoch11.db");
        let expected = if cut == 3 { first } else { last };
        let opened =
            SqliteEpochSafetyJournalV3::open_existing_v3(&target, profile.clone(), expected);
        if cut == 0 {
            assert!(opened.is_err());
            continue;
        }
        let mut owner = opened.unwrap();
        let (head, recovery) = owner.prepare_recovery_v3(expected).unwrap();
        assert_eq!(head.pin_v3(), expected);
        assert_eq!(recovery.state(), head.state_v3());
        assert_eq!(recovery.record_checksum(), head.state_record_checksum_v3());
        assert_eq!(head.state_v3().pending_sign().is_some(), cut >= 4);
        assert_eq!(
            head.migration_source_v3().initial_revision_v2(),
            first.revision
        );
        let blobs = journal11_blobs(&target);
        assert_eq!(blobs.2.len(), if cut >= 4 { 2 } else { 1 });
        with_context(fixture, Some(artifact), |context| {
            assert_eq!(
                blobs.0,
                context
                    .epoch()
                    .preparation_record_v2()
                    .unwrap()
                    .as_bytes_v2()
            );
            assert_eq!(
                blobs.2.last().unwrap().1,
                encode_epoch_safety_record_v2(head.state_v3(), context).unwrap()
            );
        });
        let source = rusqlite::Connection::open_with_flags(
            dir.path().join("chain/outgoing8.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap()
        .query_row(
            "SELECT record FROM outgoing_records WHERE revision=?1",
            [first.revision - 1],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .unwrap();
        assert_eq!(blobs.1, source);
        if cut >= 4 {
            assert!(owner
                .prepare_candidate_host_initial_recovery_v3(expected)
                .is_err());
        } else {
            let (_, driver) = owner
                .prepare_candidate_host_initial_recovery_v3(expected)
                .unwrap();
            assert!(driver.activation_persistence_pending_v2());
        }
        drop(owner);
        let rejected = if cut == 3 { last } else { first };
        if first != last {
            assert!(
                SqliteEpochSafetyJournalV3::open_existing_v3(&target, profile, rejected).is_err()
            );
        }
    }
}
