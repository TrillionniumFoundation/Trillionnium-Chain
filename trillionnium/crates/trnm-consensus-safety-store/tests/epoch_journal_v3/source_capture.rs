#[test]
fn journal11_source_capture_original_parts_double_read_and_namespace_affinity() {
    let dir = directory();
    let fixture = actual_fixture(&dir.path().join("chain"));
    journal11_source_capture_checks(dir.path(), &fixture);
}

#[inline(never)]
fn journal11_source_capture_checks(dir: &Path, fixture: &NativeOldEpochTerminalFixtureV1) {
    let (profile, prepared) = prepare11(fixture);
    let path = dir.join("capture11.db");
    let (journal, head) = SqliteEpochSafetyJournalV3::initialize_from_source_v3(
        &path,
        profile.clone(),
        EpochSafetySourceOwnerV3::Journal8(&fixture.journal, fixture.pin),
        &prepared,
    )
    .unwrap();
    let pin = head.pin_v3();
    let before = durable_image(&path);
    let source = journal.capture_successor_source_v3(pin).unwrap();
    assert_eq!(source.physical_schema_version_v3(), 11);
    assert_eq!(source.pin_v3(), pin);
    assert_eq!(source.profile_ref_v3(), profile.profile_ref_v3());
    assert_eq!(source.context_ref_v3(), profile.context_ref_v3().unwrap());
    assert_eq!(source.owner_generation_v3(), profile.owner_generation_v3());
    assert_eq!(source.state_v3(), prepared.state());
    assert_eq!(source.migration_source_v3(), head.migration_source_v3());
    assert_eq!(
        source.state_record_checksum_v3(),
        head.state_record_checksum_v3()
    );
    assert_eq!(source.transition_context_v3(), head.transition_context_v3());
    assert!(source.belongs_to_store_at_path_v3(&journal, &path));
    assert!(!source.belongs_to_store_at_path_v3(&journal, &dir.join("foreign.db")));
    assert_capture_matches_physical11(&source, &path);
    assert_eq!(
        durable_image(&path),
        before,
        "capture must not write or repair"
    );
    let mut observed = false;
    assert!(journal
        .capture_successor_source_with_observer_v3(
            EpochSafetyHeadPinV3 {
                revision: pin.revision + 1,
                ..pin
            },
            || observed = true,
        )
        .is_err());
    assert!(
        !observed,
        "a wrong expected pin must fail before the between-read hook"
    );

    // Every mutation occurs AFTER a complete successful strict first read.
    // Even identical reconstructed bytes do not authorize moving split boundaries.
    for (name, sql, same_record) in [
        ("prefix", "UPDATE epoch_provenance SET provenance=zeroblob(length(provenance))", false),
        ("relocated", "UPDATE epoch_records SET record_before=CAST(record_before || (SELECT substr(provenance,1,1) FROM epoch_provenance) AS BLOB); UPDATE epoch_provenance SET provenance=substr(provenance,2)", true),
        ("transition_bound", "UPDATE epoch_records SET transition=zeroblob(1048577)", false),
        ("origin", "UPDATE epoch_metadata SET origin=zeroblob(32)", false),
        ("schema", "CREATE TABLE unexpected_capture_object(value INTEGER) STRICT", false),
    ] {
        let copy = dir.join(format!("capture-mutant-{name}.db"));
        copy_namespace(&path, &copy);
        let owner = SqliteEpochSafetyJournalV3::open_existing_v3(&copy, profile.clone(), pin).unwrap();
        let original = journal11_blobs(&copy);
        let mut after_mutation = None;
        assert!(owner.capture_successor_source_with_observer_v3(pin, || {
            mutate(&copy, sql);
            if same_record {
                assert_eq!(journal11_blobs(&copy).2, original.2);
            }
            after_mutation = Some(durable_image(&copy));
        }).is_err(), "second read accepted {name}");
        assert_eq!(Some(durable_image(&copy)), after_mutation, "refusal must not repair {name}");
    }
    let replaced = dir.join("capture-replaced.db");
    copy_namespace(&path, &replaced);
    let replaced_owner =
        SqliteEpochSafetyJournalV3::open_existing_v3(&replaced, profile.clone(), pin).unwrap();
    let mut replaced_seen = false;
    assert!(replaced_owner
        .capture_successor_source_with_observer_v3(pin, || {
            let moved = dir.join("capture-original-inode.db");
            std::fs::rename(&replaced, &moved).unwrap();
            std::fs::copy(&moved, &replaced).unwrap();
            replaced_seen = true;
        })
        .is_err());
    assert!(
        replaced_seen,
        "namespace replacement occurs between actual reads"
    );

    // An independently opened identical copy and a fresh process affinity both
    // fail the old carrier's owner test even though all canonical bytes match.
    let other = dir.join("capture-identical.db");
    copy_namespace(&path, &other);
    let other_owner =
        SqliteEpochSafetyJournalV3::open_existing_v3(&other, profile.clone(), pin).unwrap();
    assert!(!source.belongs_to_store_at_path_v3(&other_owner, &other));
    drop(journal);
    let cold = SqliteEpochSafetyJournalV3::open_existing_v3(&path, profile, pin).unwrap();
    assert!(!source.belongs_to_store_at_path_v3(&cold, &path));
    let captured_cold = cold.capture_successor_source_v3(pin).unwrap();
    assert_eq!(captured_cold.record_bytes_v3(), source.record_bytes_v3());
    assert_eq!(
        captured_cold.transition_bytes_v3(),
        source.transition_bytes_v3()
    );
    assert_eq!(captured_cold.origin_ref_v3(), source.origin_ref_v3());
    assert!(captured_cold.belongs_to_store_at_path_v3(&cold, &path));
}

type CapturedPhysicalRow11 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32]);

fn assert_capture_matches_physical11(source: &ConfirmedEpochSuccessorSourceV3, path: &Path) {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let (before, prefix, after, transition, origin): CapturedPhysicalRow11 = connection.query_row(
        "SELECT r.record_before,p.provenance,r.record_after,r.transition,m.origin FROM epoch_records r CROSS JOIN epoch_provenance p CROSS JOIN epoch_metadata m WHERE r.revision=?1",
        [source.pin_v3().revision], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    ).unwrap();
    assert_eq!(source.before_provenance_v3(), before);
    assert_eq!(source.provenance_v3(), prefix);
    assert_eq!(source.after_provenance_v3(), after);
    assert_eq!(source.transition_bytes_v3(), transition);
    assert_eq!(source.origin_ref_v3(), origin);
    let mut full = before;
    full.extend(prefix);
    full.extend(after);
    assert_eq!(source.record_bytes_v3(), full);
}

#[cfg(feature = "candidate-epoch-host-v2")]
#[test]
fn journal11_source_capture_pending_timeout_is_inert_and_survives_cold_reopen() {
    let dir = directory();
    let fixture = actual_fixture(&dir.path().join("chain"));
    journal11_pending_capture_checks(dir.path(), &fixture);
}

#[cfg(feature = "candidate-epoch-host-v2")]
#[inline(never)]
fn journal11_pending_capture_checks(dir: &Path, fixture: &NativeOldEpochTerminalFixtureV1) {
    let (profile, prepared) = prepare11(fixture);
    let path = dir.join("capture-pending11.db");
    let (original, head) = SqliteEpochSafetyJournalV3::initialize_from_source_v3(
        &path,
        profile.clone(),
        EpochSafetySourceOwnerV3::Journal8(&fixture.journal, fixture.pin),
        &prepared,
    )
    .unwrap();
    let initial_pin = head.pin_v3();
    drop(original);
    drop(prepared);
    let mut journal =
        SqliteEpochSafetyJournalV3::open_existing_v3(&path, profile.clone(), initial_pin).unwrap();
    let (_, mut driver) = journal
        .prepare_candidate_host_initial_recovery_v3(initial_pin)
        .unwrap();
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
        .unwrap(); // fixture host's genuine initial ACK
    let effects = driver
        .step_v2(Input::LocalTimeout {
            epoch: Epoch::new(1),
            view: View::new(1),
        })
        .unwrap();
    let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
        panic!("actual timeout must persist before any signature request")
    };
    let head = journal
        .persist_exact_v3(initial_pin, request, &SafetyTransitionContextV0::ordinary())
        .unwrap();
    let pin = head.pin_v3();
    assert!(journal.capture_successor_source_v3(initial_pin).is_err());
    let before = durable_image(&path);
    let source = journal.capture_successor_source_v3(pin).unwrap();
    assert!(source.state_v3().pending_sign().is_some());
    assert_eq!(source.state_v3(), request.state());
    assert_capture_matches_physical11(&source, &path);
    assert_eq!(durable_image(&path), before);
    // Capture did not reset/replace the existing request's process affinity.
    assert_eq!(
        journal
            .persist_exact_v3(pin, request, &SafetyTransitionContextV0::ordinary())
            .unwrap()
            .pin_v3(),
        pin
    );
    drop(driver); // no timeout ACK, signature, or broadcast was released
    drop(journal);
    let mut cold = SqliteEpochSafetyJournalV3::open_existing_v3(&path, profile, pin).unwrap();
    assert!(cold
        .prepare_candidate_host_initial_recovery_v3(pin)
        .is_err());
    let recovered = cold.capture_successor_source_v3(pin).unwrap();
    assert!(recovered.state_v3().pending_sign().is_some());
    assert_eq!(recovered.record_bytes_v3(), source.record_bytes_v3());
    assert_eq!(
        recovered.transition_bytes_v3(),
        source.transition_bytes_v3()
    );
    assert_eq!(
        recovered.owner_generation_v3(),
        source.owner_generation_v3()
    );
    assert!(!source.belongs_to_store_at_path_v3(&cold, &path));
    assert!(recovered.belongs_to_store_at_path_v3(&cold, &path));
}
