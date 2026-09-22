// Real native C17 -> prepared C18. The shared prefix stops before either
// current handoff role signs; a receipt must survive cold recovery first.

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct PreHandoffInputsV1 {
    header: Vec<u8>,
    proof: Vec<u8>,
    descriptor: Vec<u8>,
    commitment: Vec<u8>,
    new_set: Vec<u8>,
    parameters: Vec<u8>,
}

impl PreHandoffInputsV1 {
    fn from_fixture(fixture: &LaterPreHandoffFixture) -> Self {
        Self {
            header: fixture.checkpoint_header.try_cev0_bytes().unwrap(),
            proof: fixture.checkpoint_finality.try_cev0_bytes().unwrap(),
            descriptor: fixture.descriptor.try_cev0_bytes().unwrap(),
            commitment: fixture.commitment.try_cev0_bytes().unwrap(),
            new_set: fixture.new_set.try_cev0_bytes().unwrap(),
            parameters: fixture.old_parameters.canonical_bytes(),
        }
    }
    fn block(&self) -> [u8; 32] {
        *decode_block_header_v0_exact(&self.header)
            .unwrap()
            .id()
            .as_bytes()
    }
    fn commit(
        &self,
        app: &DurableNativeApplicationV0,
        prepared: &crate::PreparedNativeEpochExecutionV1,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<crate::CommittedLaterEpochPreHandoffV1> {
        let descriptor = trnm_consensus_types::decode_handoff_descriptor_v0_exact(&self.descriptor)
            .map_err(|error| anyhow::anyhow!("fixture descriptor: {error:?}"))?;
        app.commit_later_epoch_pre_handoff_v1(
            prepared,
            &self.proof,
            &descriptor,
            &self.commitment,
            &self.new_set,
            &self.parameters,
            budget,
        )
    }
}

fn pre_handoff_counts(path: &std::path::Path) -> (u64, i64, i64, i64) {
    let sql =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let (sequence, pre, finality, edges): (Vec<u8>, i64, i64, i64) = sql
        .query_row(
            "SELECT durable_sequence,
        (SELECT COUNT(*) FROM native_later_epoch_pre_handoff_v1),
        (SELECT COUNT(*) FROM native_later_epoch_finality_v1),
        (SELECT COUNT(*) FROM native_later_epoch_edge_v1)
        FROM native_application_metadata_v0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    (
        u64::from_be_bytes(sequence.try_into().unwrap()),
        pre,
        finality,
        edges,
    )
}

fn pre_handoff_retained_record(path: &std::path::Path) -> [Vec<u8>; 12] {
    rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap()
        .query_row("SELECT * FROM native_later_epoch_pre_handoff_v1", [], |r| {
            let values = (0..12)
                .map(|index| r.get(index))
                .collect::<rusqlite::Result<Vec<Vec<u8>>>>()?;
            values.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .unwrap()
}

fn pre_handoff_prior_rows(
    path: &std::path::Path,
) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let sql =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    [
        "native_durable_execution_p_v0",
        "native_h1_state_sync_trusted_base_v0",
        "native_epoch_edge_v1",
        "native_durable_execution_p_v1",
        "native_later_epoch_application_finality_v1",
        "native_later_epoch_descendant_finality_v1",
    ]
    .into_iter()
    .map(|table| {
        let filter = if table == "native_durable_execution_p_v1" {
            " WHERE target_height < x'0000000000000012'"
        } else {
            ""
        };
        let mut statement = sql
            .prepare(&format!("SELECT * FROM {table}{filter} ORDER BY rowid"))
            .unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |r| {
                (0..columns)
                    .map(|i| r.get(i))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        (table.to_owned(), rows)
    })
    .collect()
}

// The only current handoff signing helper in these tests requires an actual
// freshly recovered committed native receipt. It never signs in the prefix.
#[inline(never)]
fn sign_committed_pre_handoff_anchor(
    receipt: &crate::CommittedLaterEpochPreHandoffV1,
    terminal: &BlockHeader,
) -> Vec<u8> {
    let context = receipt.strict_context();
    assert_eq!(
        context.descriptor().fields().checkpoint_block_id,
        receipt.header().id()
    );
    assert_eq!(
        context.descriptor().fields().terminal_old_block_id,
        terminal.id()
    );
    let shares = |set: &ValidatorSet, root: trnm_consensus_types::SigningRoot| {
        set.validators()
            .iter()
            .enumerate()
            .take(3)
            .map(|(index, validator)| {
                SignatureShareV0::new(
                    validator.id(),
                    Signature64::from_array(key(index).sign(root.as_bytes()).to_bytes()),
                )
                .unwrap()
            })
            .collect()
    };
    let descriptor = context.descriptor();
    let handoff = HandoffCertificateV0::new(
        descriptor.clone(),
        shares(
            context.old_validator_set(),
            descriptor.old_set_signing_root(),
        ),
        shares(
            context.new_validator_set(),
            descriptor.new_set_signing_root(),
        ),
        context.old_validator_set(),
        context.new_validator_set(),
    )
    .unwrap();
    EpochAnchorAuthorizationKernelV0::from_parts_v0(
        terminal.clone(),
        qc(terminal, context.old_validator_set()),
        handoff,
        context.old_validator_set(),
        context.new_validator_set(),
    )
    .unwrap()
    .try_cev0_bytes()
    .unwrap()
}

#[inline(never)]
fn bad_pre_handoff_proposal(fixture: &LaterPreHandoffFixture) -> Vec<u8> {
    let proof = &fixture.checkpoint_finality;
    let terminal = proof.grandchild();
    let mut signature = *terminal.proposer_signature().as_bytes();
    signature[0] ^= 1;
    let terminal = CertifiedHeaderV0::new(
        terminal.header().clone(),
        terminal.justify_qc().clone(),
        terminal.timeout_certificate().cloned(),
        None,
        Signature64::from_array(signature),
        terminal.certifying_qc().clone(),
        &fixture.old_set,
        None,
        &fixture.old_parameters,
        proof.child().header().timestamp_ms(),
    )
    .unwrap();
    FinalityProofV0::new(
        proof.finalized_block().clone(),
        proof.child().clone(),
        terminal,
        &fixture.old_set,
        None,
        &fixture.old_parameters,
        fixture.headers.last().unwrap().timestamp_ms(),
    )
    .unwrap()
    .try_cev0_bytes()
    .unwrap()
}

fn rehash_pre_handoff_record(sql: &rusqlite::Connection) {
    let store: Vec<u8> = sql
        .query_row(
            "SELECT store_id FROM native_application_metadata_v0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let row: Vec<Vec<u8>> = sql
        .query_row("SELECT * FROM native_later_epoch_pre_handoff_v1", [], |r| {
            (0..12).map(|index| r.get(index)).collect()
        })
        .unwrap();
    let proof: [u8; 32] = sha2::Sha256::digest(&row[5]).into();
    let descriptor: [u8; 32] = sha2::Sha256::digest(&row[6]).into();
    let commitment: [u8; 32] = sha2::Sha256::digest(&row[7]).into();
    let set: [u8; 32] = sha2::Sha256::digest(&row[8]).into();
    let parameters: [u8; 32] = sha2::Sha256::digest(&row[9]).into();
    let digest = trnm_finality_types::hash_domain(
        "trnm.native-application.later-pre-handoff-record.v1",
        &[
            &store,
            &row[0],
            &row[1],
            &row[2],
            &row[3],
            &row[4],
            &proof,
            &descriptor,
            &commitment,
            &set,
            &parameters,
            &row[10],
        ],
    );
    sql.execute(
        "UPDATE native_later_epoch_pre_handoff_v1 SET record_digest=?",
        [digest.as_slice()],
    )
    .unwrap();
}

#[test]
#[inline(never)]
fn later_pre_handoff_commits_before_joint_and_attaches_after_cold_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pre-handoff.sqlite3");
    let fixture = build_later_pre_handoff_fixture(&path, &[]);
    assert_eq!(fixture.edge.new_validator_set(), &fixture.old_set);
    let inputs = PreHandoffInputsV1::from_fixture(&fixture);
    let app = &fixture.application;
    let parent = app.confirmed_committed_head_v0().unwrap();
    assert_eq!(parent.height().get(), 17);
    assert!(inputs
        .commit(
            app,
            &fixture.checkpoint_prepared,
            &mut Cev0AdmissionBudgetV0::protocol_v0()
        )
        .is_err());
    app.upgrade_later_epoch_schema_v1(&parent).unwrap();
    assert!(inputs
        .commit(
            app,
            &fixture.checkpoint_prepared,
            &mut Cev0AdmissionBudgetV0::protocol_v0()
        )
        .is_err());
    app.upgrade_later_epoch_pre_handoff_schema_v1(&parent)
        .unwrap();
    let before = pre_handoff_counts(&path);
    assert_eq!((before.1, before.2, before.3), (0, 0, 0));
    app.upgrade_later_epoch_pre_handoff_schema_v1(&parent)
        .unwrap();
    assert_eq!(pre_handoff_counts(&path), before);
    let prior_rows = pre_handoff_prior_rows(&path);
    let sidecar = crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&path);
    let sidecar_bytes = std::fs::read(&sidecar).unwrap();
    let mut bad = inputs.clone();
    bad.proof = bad_pre_handoff_proposal(&fixture);
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    budget.charge_signature_work(7).unwrap();
    assert!(bad
        .commit(app, &fixture.checkpoint_prepared, &mut budget)
        .is_err());
    assert!(
        budget.signature_work() > 7,
        "canonical signature failure retains crypto charge"
    );
    assert_eq!(pre_handoff_counts(&path), before);
    assert_eq!(app.confirmed_committed_head_v0().unwrap(), parent);
    let bad_proof = bad.proof;
    let mut wrong_descriptor = fixture.descriptor.fields().clone();
    wrong_descriptor.checkpoint_state_root = StateRoot::new([99; 32]);
    let wrong_descriptor = HandoffDescriptorV0::new(wrong_descriptor)
        .unwrap()
        .try_cev0_bytes()
        .unwrap();
    let mut bad = inputs.clone();
    bad.descriptor = wrong_descriptor.clone();
    assert!(bad
        .commit(
            app,
            &fixture.checkpoint_prepared,
            &mut Cev0AdmissionBudgetV0::protocol_v0()
        )
        .is_err());
    let foreign_path = directory.path().join("foreign.sqlite3");
    copy_later_store(&path, &foreign_path);
    let foreign =
        DurableNativeApplicationV0::open(&foreign_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    assert!(inputs
        .commit(
            &foreign,
            &fixture.checkpoint_prepared,
            &mut Cev0AdmissionBudgetV0::protocol_v0()
        )
        .is_err());
    assert_eq!(pre_handoff_counts(&path), before);
    let receipt = inputs
        .commit(
            app,
            &fixture.checkpoint_prepared,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert!(receipt.belongs_to_application(app));
    assert!(!receipt.belongs_to_application(&foreign));
    let expected_head = receipt.head().clone();
    let expected_cut = receipt.committed_owner_cut_ref_v1();
    let expected_binding = receipt.strict_context().binding_ref();
    assert_eq!(expected_head.height().get(), 18);
    assert_eq!(receipt.commit_sequence(), before.0 + 1);
    assert_eq!(pre_handoff_counts(&path), (before.0 + 1, 1, 0, 0));
    assert!(app
        .inspect_later_epoch_application_edge_requirements_v1(inputs.block())
        .is_err());
    assert_eq!(
        inputs
            .commit(
                app,
                &fixture.checkpoint_prepared,
                &mut Cev0AdmissionBudgetV0::protocol_v0()
            )
            .unwrap()
            .committed_owner_cut_ref_v1(),
        expected_cut
    );
    assert_eq!(pre_handoff_prior_rows(&path), prior_rows);
    assert_eq!(std::fs::read(&sidecar).unwrap(), sidecar_bytes);
    let terminal = fixture.seal_2.clone();
    let retained = pre_handoff_retained_record(&path);
    assert_eq!(retained[5], inputs.proof);
    assert_eq!(retained[6], inputs.descriptor);
    assert_eq!(retained[10], expected_binding);
    drop(receipt);
    drop(fixture);

    // First cold recovery still has no current handoff signature or edge.
    let app =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    let receipt = app
        .recover_later_epoch_pre_handoff_v1(inputs.block())
        .unwrap();
    assert_eq!(receipt.committed_owner_cut_ref_v1(), expected_cut);
    assert_eq!(receipt.strict_context().binding_ref(), expected_binding);
    assert_eq!(app.confirmed_committed_head_v0().unwrap(), expected_head);
    assert_eq!(pre_handoff_counts(&path), (before.0 + 1, 1, 0, 0));
    assert!(
        app.upgrade_later_epoch_schema_v1(&expected_head).is_err(),
        "schema13 cannot downgrade"
    );
    let unattached_path = directory.path().join("committed-without-handoff.sqlite3");
    copy_later_store(&path, &unattached_path);
    let anchor = sign_committed_pre_handoff_anchor(&receipt, &terminal);
    assert!(foreign
        .attach_later_epoch_handoff_v1(&receipt, &anchor)
        .is_err());
    let mut bad_anchor = anchor.clone();
    *bad_anchor.last_mut().unwrap() ^= 1;
    assert!(app
        .attach_later_epoch_handoff_v1(&receipt, &bad_anchor)
        .is_err());
    assert_eq!(pre_handoff_counts(&path), (before.0 + 1, 1, 0, 0));
    let edge = app
        .attach_later_epoch_handoff_v1(&receipt, &anchor)
        .unwrap();
    let edge_digest = edge.record_digest();
    assert_eq!(edge.checkpoint_commit_sequence(), before.0 + 1);
    assert_eq!(edge.first_application_height(), 21);
    assert_eq!(
        app.attach_later_epoch_handoff_v1(&receipt, &anchor)
            .unwrap()
            .record_digest(),
        edge_digest
    );
    assert_eq!(pre_handoff_counts(&path), (before.0 + 1, 1, 1, 1));
    assert_eq!(pre_handoff_retained_record(&path), retained);
    assert_eq!(pre_handoff_prior_rows(&path), prior_rows);
    assert_eq!(std::fs::read(&sidecar).unwrap(), sidecar_bytes);
    drop(app);
    let reopened =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    assert!(
        reopened
            .attach_later_epoch_handoff_v1(&receipt, &anchor)
            .is_err(),
        "old owner receipt cannot survive reopen"
    );
    let fresh = reopened
        .recover_later_epoch_pre_handoff_v1(inputs.block())
        .unwrap();
    assert_eq!(
        reopened
            .attach_later_epoch_handoff_v1(&fresh, &anchor)
            .unwrap()
            .record_digest(),
        edge_digest
    );
    assert_eq!(pre_handoff_retained_record(&path), retained);
    drop(reopened);

    for mutation in [
        "proof",
        "descriptor",
        "binding",
        "missing",
        "ancestry",
        "sql_type",
        "downgrade",
    ] {
        let mutant = directory.path().join(format!("{mutation}.sqlite3"));
        copy_later_store(
            if mutation == "missing" {
                &unattached_path
            } else {
                &path
            },
            &mutant,
        );
        let sql = rusqlite::Connection::open(&mutant).unwrap();
        match mutation {
            "proof" => {
                sql.execute(
                    "UPDATE native_later_epoch_pre_handoff_v1 SET checkpoint_finality=?",
                    [&bad_proof],
                )
                .unwrap();
                rehash_pre_handoff_record(&sql);
            }
            "descriptor" => {
                sql.execute(
                    "UPDATE native_later_epoch_pre_handoff_v1 SET descriptor=?",
                    [&wrong_descriptor],
                )
                .unwrap();
                rehash_pre_handoff_record(&sql);
            }
            "binding" => {
                sql.execute(
                    "UPDATE native_later_epoch_pre_handoff_v1 SET strict_binding=zeroblob(32)",
                    [],
                )
                .unwrap();
                rehash_pre_handoff_record(&sql);
            }
            "missing" => {
                sql.execute("DELETE FROM native_later_epoch_pre_handoff_v1", [])
                    .unwrap();
            }
            "ancestry" => {
                sql.execute(
                    "DELETE FROM native_durable_execution_p_v1 WHERE target_height=?",
                    [14_u64.to_be_bytes().as_slice()],
                )
                .unwrap();
            }
            "sql_type" => {
                sql.execute(
                    "UPDATE native_later_epoch_pre_handoff_v1 SET descriptor='not-a-blob'",
                    [],
                )
                .unwrap();
            }
            "downgrade" => {
                sql.execute(
                    "UPDATE native_application_metadata_v0 SET schema_version=?",
                    [10_u64.to_be_bytes().as_slice()],
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        drop(sql);
        assert!(
            DurableNativeApplicationV0::open(&mutant, native_checkpoint_fixture_config_v1())
                .is_err(),
            "cold mutation {mutation}"
        );
    }
    // An identical logical database at a replacement inode is still a foreign
    // namespace for the live owner; no old receipt may attach through it.
    let replacement = directory.path().join("replacement.sqlite3");
    copy_later_store(&path, &replacement);
    let replaced_owner =
        DurableNativeApplicationV0::open(&replacement, native_checkpoint_fixture_config_v1())
            .unwrap();
    let replaced_receipt = replaced_owner
        .recover_later_epoch_pre_handoff_v1(inputs.block())
        .unwrap();
    let original_inode = directory.path().join("original-inode.sqlite3");
    std::fs::rename(&replacement, &original_inode).unwrap();
    std::fs::copy(&original_inode, &replacement).unwrap();
    let replacement_bytes = std::fs::read(&replacement).unwrap();
    assert!(replaced_owner
        .attach_later_epoch_handoff_v1(&replaced_receipt, &anchor)
        .is_err());
    assert_eq!(std::fs::read(&replacement).unwrap(), replacement_bytes);
}

#[cfg(unix)]
#[test]
#[ignore = "dedicated schema13 pre-handoff SIGKILL subprocess entry"]
fn later_pre_handoff_sigkill_child() {
    let path = std::path::PathBuf::from(std::env::var_os("TRNM_PRE_HANDOFF_CRASH_STORE").unwrap());
    let inputs: PreHandoffInputsV1 =
        serde_json::from_slice(&std::fs::read(path.with_extension("pre-handoff")).unwrap())
            .unwrap();
    let app =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    if std::env::var_os("TRNM_PRE_HANDOFF_ATTACH").is_some() {
        let receipt = app
            .recover_later_epoch_pre_handoff_v1(inputs.block())
            .unwrap();
        let anchor = std::fs::read(path.with_extension("anchor")).unwrap();
        let _edge = app
            .attach_later_epoch_handoff_v1(&receipt, &anchor)
            .unwrap();
    } else {
        let prepared = app
            .reopen_prepared_epoch_execution_v1(inputs.block())
            .unwrap();
        let _receipt = inputs
            .commit(&app, &prepared, &mut Cev0AdmissionBudgetV0::protocol_v0())
            .unwrap();
    }
    panic!("pre-handoff SIGKILL cut was not reached");
}

#[cfg(unix)]
#[test]
#[inline(never)]
fn later_pre_handoff_sigkill_commit_and_attach_cuts_preserve_original_evidence() {
    use std::os::unix::process::ExitStatusExt;
    let seed = tempfile::tempdir().unwrap();
    let seed_path = seed.path().join("prepared.sqlite3");
    let fixture = build_later_pre_handoff_fixture(&seed_path, &[]);
    let inputs = PreHandoffInputsV1::from_fixture(&fixture);
    let parent = fixture.application.confirmed_committed_head_v0().unwrap();
    fixture
        .application
        .upgrade_later_epoch_schema_v1(&parent)
        .unwrap();
    fixture
        .application
        .upgrade_later_epoch_pre_handoff_schema_v1(&parent)
        .unwrap();
    let before = pre_handoff_counts(&seed_path);
    let prior_rows = pre_handoff_prior_rows(&seed_path);
    let prepared_p = fixture.checkpoint_prepared.p_digest();
    let terminal = fixture.seal_2.clone();
    drop(fixture);
    let committed_path = seed.path().join("committed.sqlite3");
    copy_later_store(&seed_path, &committed_path);
    let app =
        DurableNativeApplicationV0::open(&committed_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    let prepared = app
        .reopen_prepared_epoch_execution_v1(inputs.block())
        .unwrap();
    let receipt = inputs
        .commit(&app, &prepared, &mut Cev0AdmissionBudgetV0::protocol_v0())
        .unwrap();
    let target = receipt.head().clone();
    let expected_cut = receipt.committed_owner_cut_ref_v1();
    let retained = pre_handoff_retained_record(&committed_path);
    // This genuine seed commit happens before the only signing call.
    let anchor = sign_committed_pre_handoff_anchor(&receipt, &terminal);
    drop(receipt);
    drop(prepared);
    drop(app);

    for stage in [
        "later_pre_handoff_before_commit",
        "later_pre_handoff_after_commit",
        "later_pre_handoff_after_fsync",
        "later_pre_handoff_attach_before_commit",
        "later_pre_handoff_attach_after_commit",
        "later_pre_handoff_attach_after_fsync",
    ] {
        let attach = stage.contains("_attach_");
        let before_commit = stage.ends_with("_before_commit");
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("application.sqlite3");
        copy_later_store(if attach { &committed_path } else { &seed_path }, &path);
        std::fs::write(
            path.with_extension("pre-handoff"),
            serde_json::to_vec(&inputs).unwrap(),
        )
        .unwrap();
        if attach {
            std::fs::write(path.with_extension("anchor"), &anchor).unwrap();
        }
        let sidecar_path = crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&path);
        let sidecar = std::fs::read(&sidecar_path).unwrap();
        let marker = directory.path().join("ready");
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "later_epoch_checkpoint_bridge::tests::later_pre_handoff_sigkill_child",
                "--nocapture",
            ])
            .env_remove("RUST_MIN_STACK")
            .env_remove("RUST_LOG")
            .env_remove("TRNM_PRE_HANDOFF_ATTACH")
            .env("TRNM_PRE_HANDOFF_CRASH_STORE", &path)
            .env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE", stage)
            .env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER", &marker);
        if attach {
            command.env("TRNM_PRE_HANDOFF_ATTACH", "1");
        }
        let mut child = command.spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        while std::fs::read_to_string(&marker).ok().as_deref() != Some(stage)
            && std::time::Instant::now() < deadline
        {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if std::fs::read_to_string(&marker).ok().as_deref() != Some(stage) {
            let _ = child.kill();
            let status = child.wait().unwrap();
            panic!("pre-handoff child missed {stage}: {status}");
        }
        child.kill().unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(9));
        let app =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        let count = pre_handoff_counts(&path);
        let prepared = app
            .reopen_prepared_epoch_execution_v1(inputs.block())
            .unwrap();
        assert_eq!(prepared.p_digest(), prepared_p);
        if !attach && before_commit {
            assert_eq!(app.confirmed_committed_head_v0().unwrap(), parent);
            assert_eq!(count, before);
            assert!(app
                .recover_later_epoch_pre_handoff_v1(inputs.block())
                .is_err());
        } else {
            assert_eq!(app.confirmed_committed_head_v0().unwrap(), target);
            let edges = i64::from(attach && !before_commit);
            assert_eq!(count, (before.0 + 1, 1, edges, edges));
            assert_eq!(pre_handoff_retained_record(&path), retained);
        }
        let receipt = inputs
            .commit(&app, &prepared, &mut Cev0AdmissionBudgetV0::protocol_v0())
            .unwrap();
        assert_eq!(receipt.committed_owner_cut_ref_v1(), expected_cut);
        assert_eq!(receipt.commit_sequence(), before.0 + 1);
        let edge = app
            .attach_later_epoch_handoff_v1(&receipt, &anchor)
            .unwrap();
        let edge_digest = edge.record_digest();
        assert_eq!(
            app.attach_later_epoch_handoff_v1(&receipt, &anchor)
                .unwrap()
                .record_digest(),
            edge_digest
        );
        assert_eq!(pre_handoff_counts(&path), (before.0 + 1, 1, 1, 1));
        assert_eq!(pre_handoff_retained_record(&path), retained);
        assert_eq!(pre_handoff_prior_rows(&path), prior_rows);
        assert_eq!(std::fs::read(&sidecar_path).unwrap(), sidecar);
        drop(edge);
        drop(receipt);
        drop(prepared);
        drop(app);
        let cold =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        let recovered = cold
            .recover_later_epoch_pre_handoff_v1(inputs.block())
            .unwrap();
        assert_eq!(recovered.committed_owner_cut_ref_v1(), expected_cut);
        assert_eq!(
            cold.attach_later_epoch_handoff_v1(&recovered, &anchor)
                .unwrap()
                .record_digest(),
            edge_digest
        );
        assert_eq!(pre_handoff_counts(&path), (before.0 + 1, 1, 1, 1));
    }
}

#[inline(never)]
fn assert_pre_handoff_export_consumers(
    app: &DurableNativeApplicationV0,
    anchor: &trnm_state_sync_v0::NativeTrustAnchorV1,
    exported: &crate::NativeEpochFinalityPathV1,
) -> (Vec<u8>, Vec<u8>) {
    use trnm_poco_node_production_v0::{
        prepare_native_live_transfer_v1, verify_retained_native_finality_path_v1,
        NativeLiveStateSyncV1,
    };
    let verified = verify_retained_native_finality_path_v1(
        anchor,
        &m15_finality_transport_copy(exported),
        trnm_state_sync_v0::NativeTrustPathLimitsV1::default(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(
        verified.terminal_header().try_cev0_bytes().unwrap(),
        exported.target_header_cev0
    );
    let (history, encoded) = assert_genuine_historical_export(app, anchor, exported);
    let historical_verified = verify_genuine_historical_path(anchor, &history).unwrap();
    assert_eq!(
        historical_verified.terminal_header(),
        verified.terminal_header()
    );
    assert_eq!(
        historical_verified.terminal_validator_set(),
        verified.terminal_validator_set()
    );
    let live = app
        .export_current_native_live_v1(
            BlockIdV0::new(*verified.terminal_header().id().as_bytes()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        crate::NativeCurrentLiveExportV1::decode(&live)
            .unwrap()
            .encode()
            .unwrap(),
        live
    );
    // Real M15/M13 proof-bound staging, never a native installation receipt.
    let transfer = prepare_native_live_transfer_v1(&verified, &live).unwrap();
    let mut staging = NativeLiveStateSyncV1::begin(verified, transfer.manifest).unwrap();
    for chunk in transfer.chunks {
        staging.accept_chunk(chunk).unwrap();
    }
    assert!(staging.missing_chunks().is_empty());
    let staged = staging.verify_complete().unwrap();
    assert_eq!(
        staged.binding().terminal_block_digest.0,
        *historical_verified.terminal_header().id().as_bytes()
    );
    assert_eq!(
        staged.binding().state_root.0,
        *historical_verified
            .terminal_header()
            .state_root()
            .as_bytes()
    );
    (live, encoded)
}

#[inline(never)]
fn assert_existing_exports_survive_pre_handoff_migration(path: &std::path::Path) {
    let LaterDescendantFixture {
        application: app,
        checkpoint_header,
        first_header,
        trust_anchor: anchor,
        ..
    } = *build_later_descendant_fixture(path);
    let checkpoint = BlockIdV0::new(*checkpoint_header.id().as_bytes()).unwrap();
    let target = BlockIdV0::new(*first_header.id().as_bytes()).unwrap();
    let before = app
        .export_epoch_finality_path_v1(checkpoint, target)
        .unwrap();
    assert_eq!(before.target_schema_version, 10);
    let (live, history) = assert_pre_handoff_export_consumers(&app, &anchor, &before);
    let head = app.confirmed_committed_head_v0().unwrap();
    assert_eq!(head.height().get(), 21);
    app.upgrade_later_epoch_pre_handoff_schema_v1(&head)
        .unwrap();
    let after = app
        .export_epoch_finality_path_v1(checkpoint, target)
        .unwrap();
    let mut expected = before;
    expected.target_schema_version = 13;
    assert_eq!(after, expected, "only physical schema metadata changes");
    assert_eq!(
        assert_pre_handoff_export_consumers(&app, &anchor, &after),
        (live.clone(), history.clone())
    );
    for unsupported in [0, 4, 9, 11, 12, 14, u64::MAX] {
        let mut bad = after.clone();
        bad.target_schema_version = unsupported;
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        budget.charge_signature_work(7).unwrap();
        assert!(matches!(
            trnm_poco_node_production_v0::verify_retained_native_finality_path_v1(
                &anchor,
                &m15_finality_transport_copy(&bad),
                trnm_state_sync_v0::NativeTrustPathLimitsV1::default(),
                &mut budget,
            ),
            Err(trnm_poco_node_production_v0::NativeEpochFinalityConsumerErrorV1::MetadataMismatch)
        ));
        assert_eq!(
            budget.signature_work(),
            7,
            "unsupported tag rejects before crypto"
        );
    }
    drop(app);
    let cold =
        DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).unwrap();
    let recovered = cold
        .export_epoch_finality_path_v1(checkpoint, target)
        .unwrap();
    assert_eq!(recovered, expected);
    assert_eq!(
        assert_pre_handoff_export_consumers(&cold, &anchor, &recovered),
        (live, history)
    );
    assert_eq!(cold.confirmed_committed_head_v0().unwrap(), head);
}

#[test]
#[inline(never)]
fn later_pre_handoff_schema13_exports_preserve_history_and_require_attachment() {
    let directory = tempfile::tempdir().unwrap();
    assert_existing_exports_survive_pre_handoff_migration(
        &directory.path().join("existing.sqlite3"),
    );

    let path = directory.path().join("new-checkpoint.sqlite3");
    let fixture = build_later_pre_handoff_fixture(&path, &[]);
    let inputs = PreHandoffInputsV1::from_fixture(&fixture);
    let old_set = fixture.old_set.clone();
    let terminal = fixture.seal_2.clone();
    let parent = fixture.application.confirmed_committed_head_v0().unwrap();
    let parent_header = fixture.headers.last().unwrap().try_cev0_bytes().unwrap();
    let set_bytes = fixture.old_set.try_cev0_bytes().unwrap();
    let parameters = fixture.old_parameters.canonical_bytes();
    // Pin genuine receiver configuration before reading either untrusted export.
    let pin =
        trnm_state_sync_v0::native_trust_anchor_pin_v1(&parent_header, &set_bytes, &parameters)
            .unwrap();
    let anchor = trnm_state_sync_v0::NativeTrustAnchorV1::from_pinned_bytes(
        &parent_header,
        &set_bytes,
        &parameters,
        pin,
    )
    .unwrap();
    let legacy_parent = BlockIdV0::new(*fixture.headers[5].id().as_bytes()).unwrap();
    fixture
        .application
        .upgrade_later_epoch_schema_v1(&parent)
        .unwrap();
    let before_live = fixture
        .application
        .export_current_native_live_v1(parent.block_id())
        .unwrap();
    assert!(fixture
        .application
        .export_epoch_finality_path_v1(legacy_parent, parent.block_id())
        .unwrap_err()
        .to_string()
        .contains("legacy ordinary proof unavailable"));
    assert!(fixture
        .application
        .export_historical_replay_v1(legacy_parent, parent.block_id())
        .is_err());
    fixture
        .application
        .upgrade_later_epoch_pre_handoff_schema_v1(&parent)
        .unwrap();
    assert_eq!(
        fixture
            .application
            .export_current_native_live_v1(parent.block_id())
            .unwrap(),
        before_live
    );
    assert!(fixture
        .application
        .export_epoch_finality_path_v1(legacy_parent, parent.block_id())
        .unwrap_err()
        .to_string()
        .contains("legacy ordinary proof unavailable"));
    assert!(fixture
        .application
        .export_historical_replay_v1(legacy_parent, parent.block_id())
        .is_err());
    drop(fixture);
    let app =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    assert_eq!(
        app.export_current_native_live_v1(parent.block_id())
            .unwrap(),
        before_live
    );
    let prepared = app
        .reopen_prepared_epoch_execution_v1(inputs.block())
        .unwrap();
    let receipt = inputs
        .commit(&app, &prepared, &mut Cev0AdmissionBudgetV0::protocol_v0())
        .unwrap();
    let target = receipt.head().block_id();
    assert!(app
        .export_epoch_finality_path_v1(parent.block_id(), target)
        .is_err());
    assert!(app
        .export_historical_replay_v1(parent.block_id(), target)
        .is_err());
    let inert_live = app.export_current_native_live_v1(target).unwrap();
    crate::recompute_native_current_live_v1(
        &inert_live,
        receipt.header(),
        &old_set,
        receipt.strict_context().old_consensus_parameters(),
    )
    .unwrap();
    let kernel = sign_committed_pre_handoff_anchor(&receipt, &terminal);
    let _edge = app
        .attach_later_epoch_handoff_v1(&receipt, &kernel)
        .unwrap();
    let exported = app
        .export_epoch_finality_path_v1(parent.block_id(), target)
        .unwrap();
    assert_eq!(exported.target_schema_version, 13);
    assert_eq!(exported.steps.len(), 1);
    assert_eq!(exported.steps[0].proof, inputs.proof);
    assert!(
        exported.steps[0].epoch_evidence.is_none(),
        "C18 remains the old epoch checkpoint"
    );
    let (live, history) = assert_pre_handoff_export_consumers(&app, &anchor, &exported);
    assert_eq!(live, inert_live);
    let decoded = crate::NativeHistoricalReplayV1::decode_v1(&history).unwrap();
    assert_eq!(decoded.records.len(), 1);
    assert!(
        decoded.activations.is_empty(),
        "checkpoint proof is not successor activation"
    );
    drop(app);
    let cold =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    assert_eq!(
        cold.export_epoch_finality_path_v1(parent.block_id(), target)
            .unwrap(),
        exported
    );
    assert_eq!(
        assert_pre_handoff_export_consumers(&cold, &anchor, &exported),
        (live, history)
    );
}
