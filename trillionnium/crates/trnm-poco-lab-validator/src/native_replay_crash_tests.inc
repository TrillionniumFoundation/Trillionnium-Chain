// M13 real process/storage cuts. The source bytes come from the existing
// actual four-owner client -> WAL -> consensus -> native finality test.
struct NativeReplayTestExportV1 {
    manifest: crate::native_replay_sync_v1::ReplayManifestV1,
    chunks: Vec<(u64, usize, Vec<u8>)>,
    head: trnm_native_application::ApplicationHeadV0,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct NativeReplayCrashFixtureV1 {
    profile: crate::native_client_profile::NativeClientProfileV1,
    manifest: crate::native_replay_sync_v1::ReplayManifestV1,
    chunks: Vec<(u64, usize, Vec<u8>)>,
}

fn native_replay_crash_config_v1(
    set: &ValidatorSet,
    profile: &crate::native_client_profile::NativeClientProfileV1,
) -> NativeApplicationConfigV0 {
    NativeApplicationConfigV0::from_canonical_lab_inputs_v0(
        CanonicalLabNativeApplicationConfigInputsV0::new(
            "native-replay-receiver",
            [0x91; 32],
            [0x92; 32],
            [0x93; 32],
            [0x94; 32],
            set.validators()[0].id(),
            set.clone(),
            ConsensusParametersV0::reference_shadow_v0(),
            profile.authorized_signers_v1().unwrap(),
            profile.governance_signer_id.clone(),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn native_replay_sigkill_matrix_v1() {
    run_native_socket_finality_case_v1(NativeSocketCaseV1::ReplaySigkill);
}

#[test]
fn native_replay_sigkill_os_child_v1() {
    let Ok(fixture_path) = std::env::var("TRNM_TEST_REPLAY_CRASH_FIXTURE") else {
        return;
    };
    let fixture: NativeReplayCrashFixtureV1 = serde_json::from_slice(
        &crate::native_replay_sync_v1::read_bounded(Path::new(&fixture_path), 4 * 1024 * 1024)
            .unwrap(),
    )
    .unwrap();
    let root = PathBuf::from(std::env::var("TRNM_TEST_REPLAY_CRASH_ROOT").unwrap());
    let cut = std::env::var("TRNM_TEST_REPLAY_CRASH_CUT").unwrap();
    let marker = PathBuf::from(std::env::var("TRNM_TEST_REPLAY_CRASH_MARKER").unwrap());
    // This fixture context is independently supplied by the parent test;
    // consensus keys/set are deterministic local test inputs, not peer data.
    let (set, _, _) = fixture_validator_set_v0(4);
    crate::native_replay_sync_v1::arm_replay_test_cut_v1(cut, marker);
    let mut receiver = crate::native_replay_sync_v1::NativeReplayReceiverV1::open(
        &root,
        native_replay_crash_config_v1(&set, &fixture.profile),
        fixture.profile.digest_v1().unwrap(),
        fixture.manifest.target_height,
        fixture.manifest,
    )
    .unwrap();
    for (height, index, bytes) in &fixture.chunks {
        receiver.accept_chunk(*height, *index, bytes).unwrap();
    }
    receiver
        .replay_and_publish(native_replay_crash_config_v1(&set, &fixture.profile))
        .unwrap();
    panic!("configured process cut was never reached");
}

fn verify_native_replay_sigkill_matrix_v1(
    temp: &tempfile::TempDir,
    set: &ValidatorSet,
    profile: &crate::native_client_profile::NativeClientProfileV1,
    export: NativeReplayTestExportV1,
    outer: &[u8],
) {
    use crate::native_replay_sync_v1::{NativeReplayReceiverV1, CHUNK_BYTES};
    use std::os::unix::{fs::MetadataExt, process::ExitStatusExt};
    let base = temp.path().join("actual-replay-sigkill");
    create_private_directory_v0(&base).unwrap();
    let executable = base.join("child-test-executable");
    // Pin the live executable inode even if Cargo has unlinked its original
    // pathname while this long-running parent test remains active.
    pin_running_test_executable_v1(&executable).unwrap();
    let fixture_path = base.join("public-fixture.json");
    let fixture = NativeReplayCrashFixtureV1 {
        profile: profile.clone(),
        manifest: export.manifest.clone(),
        chunks: export.chunks.clone(),
    };
    fs::write(&fixture_path, serde_json::to_vec(&fixture).unwrap()).unwrap();
    let config = || native_replay_crash_config_v1(set, profile);
    let profile_hash = profile.digest_v1().unwrap();
    let target = export.manifest.target_height;
    let stage_name = format!("stage-{}", hex::encode(export.manifest.digest().unwrap()));
    let cuts = [
        "manifest-published",
        "chunk-partial",
        "chunk-file-synced",
        "chunk-linked",
        "chunk-published",
        "native-prepared-h4",
        "native-committed-h4",
        "current-file-synced",
        "current-linked",
        "current-published",
    ];
    for cut in cuts {
        let case = base.join(cut);
        create_private_directory_v0(&case).unwrap();
        let root = case.join("receiver");
        let marker = case.join("reached.json");
        let log_path = case.join("child.log");
        let log = fs::File::create(&log_path).unwrap();
        let child = Command::new(&executable)
            .args([
                "--exact",
                "continuous_runtime::tests::native_replay_sigkill_os_child_v1",
                "--nocapture",
            ])
            .env("TRNM_TEST_REPLAY_CRASH_FIXTURE", &fixture_path)
            .env("TRNM_TEST_REPLAY_CRASH_ROOT", &root)
            .env("TRNM_TEST_REPLAY_CRASH_CUT", cut)
            .env("TRNM_TEST_REPLAY_CRASH_MARKER", &marker)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut guard = CompositionChildrenV0 {
            children: vec![child],
        };
        let child = &mut guard.children[0];
        let deadline = Instant::now() + Duration::from_secs(30);
        let reached = loop {
            if let Ok(bytes) = fs::read(&marker) {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    break value;
                }
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "{cut}: child exited before cut: {}",
                fs::read_to_string(&log_path).unwrap()
            );
            assert!(Instant::now() < deadline, "{cut}: child did not reach cut");
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(reached["cut"], cut);
        assert_eq!(reached["pid"], child.id());
        assert!(
            NativeReplayReceiverV1::open(
                &root,
                config(),
                profile_hash,
                target,
                export.manifest.clone()
            )
            .is_err(),
            "live child must still hold receiver ownership"
        );
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "cut must use actual SIGKILL"
        );
        guard.children.clear();

        let stage = root.join(&stage_name);
        let first_chunk = stage.join("chunk-001-00");
        let temporary_chunk = stage.join(".chunk-001-00.sync-next");
        let current = root.join("CURRENT");
        if cut == "chunk-partial" {
            assert!(!first_chunk.exists());
            assert_eq!(
                fs::metadata(&temporary_chunk).unwrap().len(),
                (export.chunks[0].2.len() / 2) as u64
            );
        }
        if cut == "chunk-file-synced" {
            assert!(!first_chunk.exists());
            assert_eq!(fs::read(&temporary_chunk).unwrap(), export.chunks[0].2);
        }
        if cut == "chunk-linked" {
            assert_eq!(
                fs::metadata(&first_chunk).unwrap().ino(),
                fs::metadata(&temporary_chunk).unwrap().ino()
            );
            assert_eq!(fs::metadata(&first_chunk).unwrap().nlink(), 2);
        }
        if cut == "current-linked" {
            assert_eq!(fs::metadata(&current).unwrap().nlink(), 2);
            assert_eq!(
                fs::metadata(&current).unwrap().ino(),
                fs::metadata(root.join(".CURRENT.sync-next")).unwrap().ino()
            );
        }
        assert_eq!(
            current.exists(),
            matches!(cut, "current-linked" | "current-published")
        );
        if cut.starts_with("native-") || cut.starts_with("current-") {
            let app = DurableNativeApplicationV0::open(stage.join("application.sqlite"), config())
                .unwrap();
            app.confirm_ordinary_schema_v0().unwrap();
            let height = if cut == "native-prepared-h4" {
                3
            } else if cut == "native-committed-h4" {
                4
            } else {
                target
            };
            assert_eq!(
                app.confirmed_committed_head_v0().unwrap().height().get(),
                height
            );
        }

        // Attacker-controlled transfer hashes do not become proof authority,
        // including after honest native K already reached height four.
        if cut == "native-committed-h4" {
            let mut malicious = export.manifest.clone();
            let first = export
                .chunks
                .iter()
                .filter(|(h, _, _)| *h == 1)
                .flat_map(|(_, _, bytes)| bytes.iter().copied())
                .collect::<Vec<_>>();
            let mut record: crate::native_replay_sync_v1::ReplayRecordV1 =
                serde_json::from_slice(&first).unwrap();
            let end = record.finality_hex.len() - 2;
            let replacement = if &record.finality_hex[end..] == "00" {
                "01"
            } else {
                "00"
            };
            record.finality_hex.replace_range(end.., replacement);
            let forged = serde_json::to_vec(&record).unwrap();
            malicious.records[0].bytes = forged.len() as u64;
            malicious.records[0].sha256 = hex::encode(Sha256::digest(&forged));
            malicious.records[0].chunk_sha256 = forged
                .chunks(CHUNK_BYTES)
                .map(|bytes| hex::encode(Sha256::digest(bytes)))
                .collect();
            let mut bad =
                NativeReplayReceiverV1::open(&root, config(), profile_hash, target, malicious)
                    .unwrap();
            for (index, bytes) in forged.chunks(CHUNK_BYTES).enumerate() {
                bad.accept_chunk(1, index, bytes).unwrap();
            }
            for (height, index, bytes) in export.chunks.iter().filter(|(h, _, _)| *h != 1) {
                bad.accept_chunk(*height, *index, bytes).unwrap();
            }
            assert!(bad.replay_and_publish(config()).is_err());
            assert!(!current.exists());
            drop(bad);
            let app = DurableNativeApplicationV0::open(stage.join("application.sqlite"), config())
                .unwrap();
            assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 4);
        }

        let mut receiver = NativeReplayReceiverV1::open(
            &root,
            config(),
            profile_hash,
            target,
            export.manifest.clone(),
        )
        .unwrap();
        for (height, index, bytes) in &export.chunks {
            // Recovery first validates any persisted bytes and repairs only
            // its exact interrupted temporary; corrupt peer input is inert.
            let _already_received = receiver.has_chunk(*height, *index).unwrap();
            let mut forged = bytes.clone();
            forged[0] ^= 1;
            assert!(receiver.accept_chunk(*height, *index, &forged).is_err());
            receiver.accept_chunk(*height, *index, bytes).unwrap();
            receiver.accept_chunk(*height, *index, bytes).unwrap();
            assert!(receiver.has_chunk(*height, *index).unwrap());
        }
        let head = receiver.replay_and_publish(config()).unwrap();
        assert_eq!(
            head, export.head,
            "{cut}: honest resume must select the same head"
        );
        let published: serde_json::Value =
            serde_json::from_slice(&fs::read(&current).unwrap()).unwrap();
        assert_eq!(
            published["manifest_sha256"],
            hex::encode(export.manifest.digest().unwrap())
        );
        assert_eq!(published["application_directory"], stage_name);
        assert_eq!(published["application_only"], true);
        assert_eq!(published["signing_authority"], false);
        assert!(!root.join(".CURRENT.sync-next").exists());
        drop(receiver);
        let mut retry = NativeReplayReceiverV1::open(
            &root,
            config(),
            profile_hash,
            target,
            export.manifest.clone(),
        )
        .unwrap();
        assert_eq!(retry.replay_and_publish(config()).unwrap(), head);
        drop(retry);
        let app =
            DurableNativeApplicationV0::open(stage.join("application.sqlite"), config()).unwrap();
        let business = app
            .read_finalized_by_height_v0(trnm_native_application::HeightV0::new(4))
            .unwrap();
        assert_eq!(
            business.executed_v0().request().transactions(),
            &[outer.to_vec()]
        );
        let parent_time = app
            .read_finalized_by_height_v0(trnm_native_application::HeightV0::new(target))
            .unwrap()
            .executed_v0()
            .request()
            .timestamp_ms();
        let preview = |transactions| {
            trnm_native_execution_v0::NativeBlockPreviewRequestV0::new(
                trnm_native_application::ChainIdV0::new(set.chain_id().as_str()).unwrap(),
                trnm_native_application::GenesisHashV0::new(*set.genesis_hash().as_bytes())
                    .unwrap(),
                head.clone(),
                trnm_native_application::HeightV0::new(target + 1),
                parent_time + 1,
                trnm_native_application::ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
                transactions,
            )
            .unwrap()
        };
        assert!(app.preview_block_v0(&preview(Vec::new())).is_ok());
        assert_eq!(app.preview_block_v0(&preview(vec![outer.to_vec()])).unwrap_err().code(), trnm_native_execution_v0::NativeApplicationExecutionErrorCodeV0::DeterministicallyInvalid);
        assert_eq!(app.confirmed_committed_head_v0().unwrap(), head);
        eprintln!("native replay actual SIGKILL recovery passed: {cut}");
    }
}
