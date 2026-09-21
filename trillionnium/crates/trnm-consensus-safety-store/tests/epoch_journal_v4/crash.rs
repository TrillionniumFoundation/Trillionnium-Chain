// Each child obtains its source through the same genuine native/Core flow as
// the ordinary test. Only independently fsynced host-intent comparison data
// crosses the process boundary; neither SQL promotion nor a fake ACK is used.
const JOURNAL12_CHILD_DIR: &str = "TRNM_JOURNAL12_CHILD_DIR";
const JOURNAL12_CHILD_CUT: &str = "TRNM_JOURNAL12_CHILD_CUT";

struct Journal12CrashFacts {
    source_pin: EpochSafetyHeadPinV3,
    source_artifact: ValidatedPayloadArtifactRefV0,
    target_artifact: ValidatedPayloadArtifactRefV0,
    source_checksum: [u8; 32],
    source_profile: [u8; 32],
    target_profile: [u8; 32],
}

#[test]
#[ignore = "dedicated child invoked by journal12_six_sigkill_cuts_keep_actual_source_and_prefix"]
fn journal12_sigkill_child() {
    let path = PathBuf::from(std::env::var_os(JOURNAL12_CHILD_DIR).unwrap());
    let cut = std::env::var(JOURNAL12_CHILD_CUT).unwrap().parse().unwrap();
    let mut driver = actual_epoch_driver_v4(&path);
    driver.execute_epoch_to_terminal();
    journal12_crash_child(&path, cut, driver);
}

#[inline(never)]
fn journal12_crash_child(path: &Path, cut: usize, mut live: Box<ActualEpochDriverV4>) {
    let source_artifact = live
        .core()
        .state()
        .epoch_state_v1()
        .unwrap()
        .checkpoint_artifact();
    let (_, artifact, _) = live.attach_next_epoch();
    let (profile, prepared) = live.prepare_successor(artifact);
    let ActualJournalV4::Eleven {
        owner: source,
        profile: source_profile,
        pin,
    } = &live.journal
    else {
        panic!("actual source11")
    };
    let original = source.fresh_read_v3(*pin).unwrap();
    assert_eq!(original.state_v3().finalized().height(), Height::new(18));
    assert_eq!(
        original.state_v3().application_applied(),
        original.state_v3().finalized()
    );
    assert!(original.state_v3().pending_sign().is_none());
    let facts = Journal12CrashFacts {
        source_pin: *pin,
        source_artifact,
        target_artifact: artifact,
        source_checksum: original.state_record_checksum_v3(),
        source_profile: source_profile.profile_ref_v3(),
        target_profile: profile.profile_ref_v4(),
    };
    let target = path.join("epoch12-crash.db");
    let (owner, head) = SqliteEpochSafetyJournalV4::initialize_with_observer_v4(
        &target,
        profile.clone(),
        live.journal.source(),
        &prepared,
        |stage, pin| {
            if cut < 3 && journal11_cut_index(stage) == cut {
                journal12_die_at_cut(path, &[pin], &facts);
            }
            Ok(())
        },
    )
    .unwrap();
    let initial = head.pin_v4();
    drop(owner);
    drop(prepared);
    journal12_crash_append(path, cut, profile, initial, &facts);
}

#[inline(never)]
fn journal12_crash_append(
    path: &Path,
    cut: usize,
    profile: EpochSafetyJournalProfileV4,
    initial: EpochSafetyHeadPinV4,
    facts: &Journal12CrashFacts,
) {
    let mut owner = SqliteEpochSafetyJournalV4::open_existing_v4(
        path.join("epoch12-crash.db"),
        profile,
        initial,
    )
    .unwrap();
    let (_, mut driver) = owner
        .prepare_candidate_host_initial_recovery_v4(initial)
        .unwrap();
    owner
        .confirm_exact_request_v4(
            initial,
            driver.initial_persistence_v2(),
            &SafetyTransitionContextV0::ordinary(),
        )
        .unwrap();
    let effects = driver
        .step_v2(Input::StorageAck {
            barrier: driver.initial_persistence_v2().barrier(),
        })
        .unwrap();
    assert!(effects
        .iter()
        .all(|e| matches!(e, Effect::ArmViewTimer { .. })));
    let effects = driver
        .step_v2(Input::LocalTimeout {
            epoch: Epoch::new(2),
            view: View::new(1),
        })
        .unwrap();
    let [Effect::PersistSafetyState(request)] = effects.as_slice() else {
        panic!("real timeout persists before requesting any signature")
    };
    owner
        .persist_with_pin_observer_v4(
            initial,
            request,
            &SafetyTransitionContextV0::ordinary(),
            |stage, pin| {
                if journal11_cut_index(stage) + 3 == cut {
                    journal12_die_at_cut(path, &[initial, pin], facts);
                }
                Ok(())
            },
        )
        .unwrap();
    panic!("selected SIGKILL cut did not terminate the actual child");
}

fn journal12_die_at_cut(
    path: &Path,
    pins: &[EpochSafetyHeadPinV4],
    facts: &Journal12CrashFacts,
) -> ! {
    use std::io::Write;
    let mut bytes = Vec::new();
    for pin in pins {
        bytes.extend(pin.journal_id);
        bytes.extend(pin.revision.to_le_bytes());
        bytes.extend(pin.chain_checksum);
    }
    bytes.extend(facts.source_pin.journal_id);
    bytes.extend(facts.source_pin.revision.to_le_bytes());
    bytes.extend(facts.source_pin.chain_checksum);
    for artifact in [facts.source_artifact, facts.target_artifact] {
        bytes.extend(artifact.overlay().overlay_checksum());
        bytes.extend(artifact.source_artifact_checksum());
    }
    bytes.extend(facts.source_checksum);
    bytes.extend(facts.source_profile);
    bytes.extend(facts.target_profile);
    let mut marker = std::fs::File::create(path.join("independent12-cut")).unwrap();
    marker.write_all(&bytes).unwrap();
    marker.sync_all().unwrap();
    std::fs::File::open(path).unwrap().sync_all().unwrap();
    unsafe {
        libc::kill(libc::getpid(), libc::SIGKILL);
    }
    panic!("SIGKILL did not terminate child");
}

#[test]
fn journal12_six_sigkill_cuts_keep_actual_source_and_prefix() {
    let reference = directory();
    let mut live = actual_epoch_driver_v4(reference.path());
    live.execute_epoch_to_terminal();
    let _ = live.attach_next_epoch();
    journal12_crash_parent(&live);
}

#[inline(never)]
fn journal12_crash_parent(reference: &ActualEpochDriverV4) {
    for cut in 0..6 {
        let dir = directory();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "journal12::journal12_sigkill_child",
                "--ignored",
                "--nocapture",
            ])
            .env(JOURNAL12_CHILD_DIR, dir.path())
            .env(JOURNAL12_CHILD_CUT, cut.to_string())
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
                panic!("Journal12 cut {cut} exceeded 90 seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "actual selected cut {cut}"
        );
        journal12_check_crash(reference, dir.path(), cut);
    }
}

#[inline(never)]
fn journal12_check_crash(reference: &ActualEpochDriverV4, path: &Path, cut: usize) {
    let marker = std::fs::read(path.join("independent12-cut")).unwrap();
    let count = if cut < 3 { 1 } else { 2 };
    assert_eq!(marker.len(), count * 72 + 296);
    let pin = |bytes: &[u8]| EpochSafetyHeadPinV4 {
        journal_id: bytes[..32].try_into().unwrap(),
        revision: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
        chain_checksum: bytes[40..72].try_into().unwrap(),
    };
    let first = pin(&marker[..72]);
    let last = pin(&marker[(count - 1) * 72..count * 72]);
    let offset = count * 72;
    let raw_source = pin(&marker[offset..offset + 72]);
    let source_pin = EpochSafetyHeadPinV3 {
        journal_id: raw_source.journal_id,
        revision: raw_source.revision,
        chain_checksum: raw_source.chain_checksum,
    };
    let artifact = |index: usize| {
        let header = reference.contexts[index]
            .activation()
            .old_checkpoint_finality()
            .finalized_block()
            .header();
        let start = offset + 72 + index * 64;
        ValidatedPayloadArtifactRefV0::new(
            BlockIdOverlayRefV0::new(
                header.id(),
                header.parent_id(),
                marker[start..start + 32].try_into().unwrap(),
            ),
            marker[start + 32..start + 64].try_into().unwrap(),
        )
    };
    let source_profile = with_epoch_context_v4(
        &reference.contexts[..1],
        &reference.ancestries[..1],
        artifact(0),
        2,
        |context| {
            EpochSafetyJournalProfileV3::from_journal8_v3(&reference.source_commissioning, context)
                .unwrap()
        },
    );
    let target_profile = with_epoch_context_v4(
        &reference.contexts,
        &reference.ancestries,
        artifact(1),
        3,
        |context| EpochSafetyJournalProfileV4::from_journal11_v4(&source_profile, context).unwrap(),
    );
    assert_eq!(
        source_profile.profile_ref_v3().as_slice(),
        &marker[offset + 232..offset + 264]
    );
    assert_eq!(
        target_profile.profile_ref_v4().as_slice(),
        &marker[offset + 264..offset + 296]
    );
    let source = SqliteEpochSafetyJournalV3::open_existing_v3(
        path.join("epoch11.db"),
        source_profile,
        source_pin,
    )
    .unwrap();
    let source_head = source.fresh_read_v3(source_pin).unwrap();
    assert_eq!(
        source_head.state_record_checksum_v3().as_slice(),
        &marker[offset + 200..offset + 232]
    );
    assert_eq!(source_head.state_v3().finalized().height(), Height::new(18));
    assert_eq!(
        source_head.state_v3().application_applied(),
        source_head.state_v3().finalized()
    );
    assert!(source_head.state_v3().pending_sign().is_none());
    let original_source = original_prefix_record_v4(source.path_v3());
    let expected = if cut == 3 { first } else { last };
    let opened = SqliteEpochSafetyJournalV4::open_existing_v4(
        path.join("epoch12-crash.db"),
        target_profile,
        expected,
    );
    if cut == 0 {
        assert!(opened.is_err());
        return;
    }
    let mut target = opened.unwrap();
    let (head, recovered) = target.prepare_recovery_v4(expected).unwrap();
    assert_eq!(head.state_v4(), recovered.state());
    assert_eq!(head.state_record_checksum_v4(), recovered.record_checksum());
    assert_eq!(head.state_v4().pending_sign().is_some(), cut >= 4);
    assert_eq!(head.revision_v4(), first.revision + u64::from(cut >= 4));
    assert_eq!(
        head.migration_source_v4().pin_v4().kind,
        EpochSafetySourceKindV4::Journal11
    );
    assert_eq!(
        head.migration_source_v4().state_record_checksum_v4(),
        source_head.state_record_checksum_v3()
    );
    let (prefix, source_record, rows) = journal11_blobs(target.path_v4());
    assert_eq!(
        source_record, original_source,
        "SIGKILL cannot rewrite original source evidence"
    );
    assert_eq!(rows.len(), if cut >= 4 { 2 } else { 1 });
    assert_eq!(
        prefix,
        head.state_v4()
            .epoch_state_v1()
            .unwrap()
            .preparation_record_v2()
            .unwrap()
            .as_bytes_v2()
    );
    if cut >= 4 {
        assert!(
            target
                .prepare_candidate_host_initial_recovery_v4(expected)
                .is_err(),
            "pending signature is not an initial recovery cut"
        );
    } else {
        let (_, driver) = target
            .prepare_candidate_host_initial_recovery_v4(expected)
            .unwrap();
        let again = target
            .persist_exact_v4(
                expected,
                driver.initial_persistence_v2(),
                &SafetyTransitionContextV0::ordinary(),
            )
            .unwrap();
        assert_eq!(again.pin_v4(), expected);
        assert_eq!(
            journal11_blobs(target.path_v4()),
            (prefix, source_record, rows)
        );
        assert!(
            driver.activation_persistence_pending_v2(),
            "recovery test never ACKs an unreconciled host"
        );
    }
}
