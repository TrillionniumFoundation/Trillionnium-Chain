// M06 producer checks for the M08 schema10 retained ordinary-finality contract.
// Included only inside later_epoch_checkpoint_bridge's test module.

fn copy_later_store(source: &std::path::Path, target: &std::path::Path) {
    std::fs::copy(source, target).unwrap();
    std::fs::copy(
        crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(source),
        crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(target),
    )
    .unwrap();
}

fn downgrade_to_schema9(path: &std::path::Path) {
    let sql = rusqlite::Connection::open(path).unwrap();
    sql.execute_batch("DROP TABLE native_later_epoch_descendant_finality_v1;")
        .unwrap();
    sql.execute(
        "UPDATE native_application_metadata_v0 SET schema_version=? WHERE singleton=1",
        [9_u64.to_be_bytes().as_slice()],
    )
    .unwrap();
}

fn assert_schema9_prepared_descendant_migration(source: &std::path::Path) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("prepared-schema9.sqlite3");
    copy_later_store(source, &path);
    downgrade_to_schema9(&path);
    let app =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    let head = app.confirmed_committed_head_v0().unwrap();
    assert_eq!(head.height().get(), 21);
    let sql = rusqlite::Connection::open(&path).unwrap();
    let before: Vec<u8> = sql
        .query_row(
            "SELECT durable_sequence FROM native_application_metadata_v0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    app.upgrade_later_epoch_schema_v1(&head)
        .expect("schema9 C21 plus Prepared C22 must migrate");
    assert_eq!(app.confirmed_committed_head_v0().unwrap(), head);
    let (version, after): (Vec<u8>, Vec<u8>) = sql
        .query_row(
            "SELECT schema_version,durable_sequence FROM native_application_metadata_v0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(version, 10_u64.to_be_bytes());
    assert_eq!(after, before);
    let bytes = std::fs::read(&path).unwrap();
    app.upgrade_later_epoch_schema_v1(&head)
        .expect("schema10 exact migration retry");
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

fn assert_schema9_committed_descendant_migration_refused(source: &std::path::Path) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("committed-schema9.sqlite3");
    copy_later_store(source, &path);
    downgrade_to_schema9(&path);
    let app =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    let head = app.confirmed_committed_head_v0().unwrap();
    assert!(head.height().get() >= 22);
    let bytes = std::fs::read(&path).unwrap();
    let sidecar = crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&path);
    let sidecar_bytes = std::fs::read(&sidecar).unwrap();
    let error = app.upgrade_later_epoch_schema_v1(&head).unwrap_err();
    assert!(
        error.to_string().contains(
            "schema-9 committed later descendant requires retained original finality proof"
        ),
        "{error:#}"
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        bytes,
        "refused migration must not modify database bytes"
    );
    assert_eq!(std::fs::read(&sidecar).unwrap(), sidecar_bytes);
    assert_eq!(app.confirmed_committed_head_v0().unwrap(), head);
}

#[inline(never)]
fn ordinary_later_proof(
    parent: &BlockHeader,
    headers: &[BlockHeader; 3],
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> Vec<u8> {
    FinalityProofV0::new(
        certified(
            headers[0].clone(),
            qc(parent, set),
            set,
            parameters,
            parent.timestamp_ms(),
        ),
        certified(
            headers[1].clone(),
            qc(&headers[0], set),
            set,
            parameters,
            headers[0].timestamp_ms(),
        ),
        certified(
            headers[2].clone(),
            qc(&headers[1], set),
            set,
            parameters,
            headers[1].timestamp_ms(),
        ),
        set,
        None,
        parameters,
        parent.timestamp_ms(),
    )
    .unwrap()
    .try_cev0_bytes()
    .unwrap()
}

fn later_regular_header(set: &ValidatorSet, parent: &BlockHeader, timestamp: u64) -> BlockHeader {
    checkpoint_like_header_at_view(
        set,
        BlockKind::Regular,
        parent.height().get() + 1,
        parent.id(),
        parent.state_root(),
        None,
        timestamp,
        parent.payload_root(),
        parent.receipts_root(),
        parent.evidence_root(),
        parent.view().get() + 1,
    )
}

#[inline(never)]
fn assert_valid_ordinary_later_proof(
    proof: &[u8],
    parent: &BlockHeader,
    header: &BlockHeader,
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) {
    let expected = trnm_consensus_crypto::FinalityExpectationV0 {
        block_id: header.id(),
        height: header.height(),
        state_root: header.state_root(),
        receipts_root: header.receipts_root(),
        evidence_root: header.evidence_root(),
        parent_id: parent.id(),
        parent_height: parent.height(),
        parent_timestamp_ms: parent.timestamp_ms(),
    };
    let verified = trnm_consensus_crypto::decode_verify_finality_proof_strict_v0(
        trnm_consensus_crypto::POCO_THREE_CHAIN_PROOF_CLASS_V0,
        proof,
        set,
        parameters,
        expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .expect("fixture proof must independently pass strict verification");
    assert_eq!(verified.proof().finalized_block().header(), header);
}

fn descendant_record_digest(row: &[Vec<u8>; 7]) -> [u8; 32] {
    trnm_finality_types::hash_domain(
        "trnm.native-application.later-epoch-descendant-finality.v1",
        &[
            &native_checkpoint_fixture_config_v1().store_id(),
            &row[0],
            &row[1],
            &row[2],
            &row[3],
            &row[5],
        ],
    )
}

#[inline(never)]
fn assert_signature_mutant_is_canonical(
    proof: &[u8],
    parent: &BlockHeader,
    header: &BlockHeader,
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) {
    let mut forged = proof.to_vec();
    *forged.last_mut().unwrap() ^= 1;
    let decoded = trnm_consensus_types::decode_finality_proof_v0_exact(
        &forged,
        set,
        parameters,
        parent.timestamp_ms(),
    )
    .expect("signature mutant must preserve canonical framing and relations");
    assert_eq!(decoded.try_cev0_bytes().unwrap(), forged);
    let expected = trnm_consensus_crypto::FinalityExpectationV0 {
        block_id: header.id(),
        height: header.height(),
        state_root: header.state_root(),
        receipts_root: header.receipts_root(),
        evidence_root: header.evidence_root(),
        parent_id: parent.id(),
        parent_height: parent.height(),
        parent_timestamp_ms: parent.timestamp_ms(),
    };
    assert!(
        trnm_consensus_crypto::decode_verify_finality_proof_strict_v0(
            trnm_consensus_crypto::POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &forged,
            set,
            parameters,
            expected,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err(),
        "well-formed signature mutant must fail strict cryptographic verification"
    );
}

#[inline(never)]
fn wrong_descendant_authority_proofs(
    parent: &BlockHeader,
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
) -> Vec<(&'static str, Vec<u8>)> {
    let other_set = ValidatorSet::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        set.consensus_parameters_hash(),
        set.validators()
            .iter()
            .map(|v| {
                Validator::new(
                    v.id(),
                    v.consensus_key(),
                    trnm_consensus_types::VotingPower::new(v.voting_power().get() + 1).unwrap(),
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    [("parent", set), ("set", &other_set)]
        .into_iter()
        .map(|(name, signing_set)| {
            let other_parent = checkpoint_like_header_at_view(
                signing_set,
                BlockKind::EpochHandoff,
                parent.height().get(),
                parent.parent_id(),
                parent.state_root(),
                None,
                parent.timestamp_ms() + 1,
                parent.payload_root(),
                parent.receipts_root(),
                parent.evidence_root(),
                parent.view().get(),
            );
            let h22 = later_regular_header(signing_set, &other_parent, 22_000);
            let h23 = later_regular_header(signing_set, &h22, 23_000);
            let h24 = later_regular_header(signing_set, &h23, 24_000);
            let bytes = ordinary_later_proof(
                &other_parent,
                &[h22.clone(), h23, h24],
                signing_set,
                parameters,
            );
            assert_valid_ordinary_later_proof(&bytes, &other_parent, &h22, signing_set, parameters);
            (name, bytes)
        })
        .collect()
}

fn descendant_execution_request(
    request: &NativeBlockPreviewRequestV0,
    header: &BlockHeader,
) -> NativeBlockExecutionRequestV0 {
    NativeBlockExecutionRequestV0::new(
        request.chain_id().clone(),
        request.genesis_hash(),
        request.parent().clone(),
        BlockIdV0::new(*header.id().as_bytes()).unwrap(),
        request.height(),
        request.timestamp_ms(),
        request.active_validator_set_id(),
        Vec::new(),
        NativeExpectedBlockCommitmentsV0::new(
            Hash32V0::new(*header.payload_root().as_bytes()),
            trnm_native_application::StateRootV0::new(*header.state_root().as_bytes()).unwrap(),
            trnm_native_application::ReceiptsRootV0::new(*header.receipts_root().as_bytes())
                .unwrap(),
            Hash32V0::new(*header.evidence_root().as_bytes()),
        )
        .unwrap(),
    )
    .unwrap()
}

fn write_descendant_record(sql: &rusqlite::Connection, block: &[u8], row: &[Vec<u8>; 7]) {
    sql.execute(
        "UPDATE native_later_epoch_descendant_finality_v1 SET block_id=?,p_digest=?,commit_sequence=?,edge_binding=?,proof=?,proof_digest=?,record_digest=? WHERE block_id=?",
        rusqlite::params![row[0], row[1], row[2], row[3], row[4], row[5], row[6], block],
    ).unwrap();
}

fn assert_descendant_ledger_recovery(
    path: &std::path::Path,
    block: &[u8; 32],
    wrong_target: &[u8],
    wrong_authority: &[(&str, Vec<u8>)],
) {
    let sql = rusqlite::Connection::open(path).unwrap();
    let original: [Vec<u8>; 7] = sql.query_row(
        "SELECT block_id,p_digest,commit_sequence,edge_binding,proof,proof_digest,record_digest FROM native_later_epoch_descendant_finality_v1 WHERE block_id=?",
        [block.as_slice()], |r| Ok([r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?]),
    ).unwrap();
    assert_eq!(original[5], sha2::Sha256::digest(&original[4]).to_vec());
    assert_eq!(original[6], descendant_record_digest(&original));
    let strict: i64 = sql.query_row(
        "SELECT strict FROM pragma_table_list WHERE name='native_later_epoch_descendant_finality_v1'", [], |r| r.get(0),
    ).unwrap();
    assert_eq!(strict, 1);
    assert!(sql
        .execute(
            "UPDATE native_later_epoch_descendant_finality_v1 SET proof='text' WHERE block_id=?",
            [block.as_slice()]
        )
        .is_err());
    assert!(sql
        .execute(
            "UPDATE native_later_epoch_descendant_finality_v1 SET proof=x'' WHERE block_id=?",
            [block.as_slice()]
        )
        .is_err());
    assert!(sql.execute("UPDATE native_later_epoch_descendant_finality_v1 SET proof_digest=x'01' WHERE block_id=?", [block.as_slice()]).is_err());
    // Simulate a corrupted image that bypassed SQL CHECK constraints. Recovery
    // still rejects before selecting an oversized proof blob into memory.
    sql.execute_batch("PRAGMA ignore_check_constraints=ON;")
        .unwrap();
    sql.execute("UPDATE native_later_epoch_descendant_finality_v1 SET proof=zeroblob(8388609) WHERE block_id=?", [block.as_slice()]).unwrap();
    assert!(DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err());
    write_descendant_record(&sql, block, &original);
    sql.execute_batch("PRAGMA ignore_check_constraints=OFF;")
        .unwrap();
    let predecessor: Vec<u8> = sql
        .query_row(
            "SELECT predecessor_edge FROM native_later_epoch_edge_v1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    for mutation in ["signature", "p_digest", "lineage", "target"] {
        let mut forged = original.clone();
        match mutation {
            "signature" => *forged[4].last_mut().unwrap() ^= 1,
            "p_digest" => forged[1][0] ^= 1,
            "lineage" => forged[3] = predecessor.clone(),
            "target" => forged[4] = wrong_target.to_vec(),
            _ => unreachable!(),
        }
        forged[5] = sha2::Sha256::digest(&forged[4]).to_vec();
        forged[6] = descendant_record_digest(&forged).to_vec();
        write_descendant_record(&sql, block, &forged);
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err(),
            "rehashed descendant {mutation} must fail cold audit"
        );
        write_descendant_record(&sql, block, &original);
    }
    for (name, proof) in wrong_authority {
        let mut forged = original.clone();
        forged[4] = proof.clone();
        forged[5] = sha2::Sha256::digest(&forged[4]).to_vec();
        forged[6] = descendant_record_digest(&forged).to_vec();
        write_descendant_record(&sql, block, &forged);
        assert!(
            DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err(),
            "signed proof with wrong {name} must fail exact ordinary recovery"
        );
        write_descendant_record(&sql, block, &original);
    }
    // An extra proof for a still-Prepared P must never manufacture commitment.
    let (prepared_block, prepared_digest): (Vec<u8>, Vec<u8>) = sql
        .query_row(
            "SELECT block_id,p_digest FROM native_durable_execution_p_v1 WHERE status=0 LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let mut extra = original.clone();
    extra[0] = prepared_block.clone();
    extra[1] = prepared_digest;
    extra[2] = 999_999_u64.to_be_bytes().to_vec();
    extra[6] = descendant_record_digest(&extra).to_vec();
    sql.execute(
        "INSERT INTO native_later_epoch_descendant_finality_v1 VALUES (?,?,?,?,?,?,?)",
        rusqlite::params![extra[0], extra[1], extra[2], extra[3], extra[4], extra[5], extra[6]],
    )
    .unwrap();
    assert!(
        DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err(),
        "Prepared P cannot acquire authority from an extra ledger row"
    );
    sql.execute(
        "DELETE FROM native_later_epoch_descendant_finality_v1 WHERE block_id=?",
        [prepared_block],
    )
    .unwrap();
    sql.execute(
        "DELETE FROM native_later_epoch_descendant_finality_v1 WHERE block_id=?",
        [block.as_slice()],
    )
    .unwrap();
    assert!(
        DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_err(),
        "each committed later Regular P requires its original proof"
    );
    sql.execute(
        "INSERT INTO native_later_epoch_descendant_finality_v1 VALUES (?,?,?,?,?,?,?)",
        rusqlite::params![
            original[0],
            original[1],
            original[2],
            original[3],
            original[4],
            original[5],
            original[6]
        ],
    )
    .unwrap();
    assert!(DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).is_ok());
}

#[cfg(unix)]
#[test]
#[ignore = "dedicated SIGKILL subprocess entry"]
fn later_descendant_c22_sigkill_child() {
    let path = std::path::PathBuf::from(
        std::env::var_os("TRNM_LATER_DESCENDANT_CRASH_STORE").expect("child store"),
    );
    let encoded: Vec<Vec<u8>> =
        serde_json::from_slice(&std::fs::read(path.with_extension("descendant-proof")).unwrap())
            .unwrap();
    let header = decode_block_header_v0_exact(&encoded[0]).unwrap();
    let app =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    let prepared = app
        .reopen_prepared_epoch_execution_v1(*header.id().as_bytes())
        .unwrap();
    let _committed = app
        .commit_epoch_finality_bytes_v1(
            &prepared,
            &encoded[1],
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    panic!("SIGKILL stage was not reached");
}

#[cfg(unix)]
#[test]
fn later_descendant_c22_sigkill_commit_cuts_recover_exact_p_and_proof() {
    let seed_directory = tempfile::tempdir().unwrap();
    let seed_path = seed_directory.path().join("prepared-seed.sqlite3");
    let fixture = build_later_descendant_fixture(&seed_path);
    let encoded = vec![
        fixture.c22_header.try_cev0_bytes().unwrap(),
        fixture.c22_proof.clone(),
    ];
    let first_block = *fixture.first_header.id().as_bytes();
    let c22_block = *fixture.c22_header.id().as_bytes();
    let expected_p = fixture.prepared.p_digest();
    let retained_c21 = |sql: &rusqlite::Connection| -> [Vec<u8>; 4] {
        sql.query_row(
            "SELECT e.record_digest,e.consumed_sequence,f.proof,f.record_digest
             FROM native_later_epoch_edge_v1 e JOIN native_later_epoch_application_finality_v1 f
             ON f.edge_binding=e.successor_binding",
            [],
            |r| Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?]),
        )
        .unwrap()
    };
    let expected_c21 = retained_c21(&rusqlite::Connection::open(&seed_path).unwrap());
    drop(fixture);
    for stage in [
        "later_descendant_before_commit",
        "later_descendant_after_commit",
        "later_descendant_after_fsync",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("application.sqlite3");
        copy_later_store(&seed_path, &path);
        std::fs::write(
            path.with_extension("descendant-proof"),
            serde_json::to_vec(&encoded).unwrap(),
        )
        .unwrap();
        let marker = directory.path().join("ready");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "later_epoch_checkpoint_bridge::tests::later_descendant_c22_sigkill_child",
                "--nocapture",
            ])
            .env_remove("RUST_MIN_STACK")
            .env("TRNM_LATER_DESCENDANT_CRASH_STORE", &path)
            .env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE", stage)
            .env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER", &marker)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        while !marker.exists() && std::time::Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !marker.exists() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("C22 child did not reach {stage} within 90 seconds");
        }
        child.kill().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            child.wait().unwrap().signal(),
            Some(9),
            "real SIGKILL required"
        );
        let app =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        let before_commit = stage == "later_descendant_before_commit";
        assert_eq!(
            app.confirmed_committed_head_v0().unwrap().height().get(),
            if before_commit { 21 } else { 22 }
        );
        let sql = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            retained_c21(&sql),
            expected_c21,
            "C22 crash recovery must preserve exact C21 authority and proof"
        );
        let (phase, consumed, application_count, ordinary_count): (i64,Vec<u8>,i64,i64) = sql.query_row(
            "SELECT phase,consumed_block,(SELECT COUNT(*) FROM native_later_epoch_application_finality_v1),(SELECT COUNT(*) FROM native_later_epoch_descendant_finality_v1) FROM native_later_epoch_edge_v1", [],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).unwrap();
        assert_eq!(
            (phase, consumed, application_count),
            (1, first_block.to_vec(), 1)
        );
        assert_eq!(ordinary_count, i64::from(!before_commit));
        let prepared = app.reopen_prepared_epoch_execution_v1(c22_block).unwrap();
        assert_eq!(prepared.p_digest(), expected_p);
        let committed = app
            .commit_epoch_finality_bytes_v1(
                &prepared,
                &encoded[1],
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        let retry = app
            .commit_epoch_finality_bytes_v1(
                &prepared,
                &encoded[1],
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(retry.commit_sequence(), committed.commit_sequence());
        let (proof,p_digest,sequence): (Vec<u8>,Vec<u8>,Vec<u8>) = sql.query_row("SELECT proof,p_digest,commit_sequence FROM native_later_epoch_descendant_finality_v1 WHERE block_id=?", [c22_block.as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(proof, encoded[1]);
        assert_eq!(p_digest, expected_p);
        assert_eq!(sequence, committed.commit_sequence().to_be_bytes());
        assert_eq!(
            retained_c21(&sql),
            expected_c21,
            "C22 retry must preserve exact C21 authority and proof"
        );
        drop(app);
        let cold =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        assert_eq!(
            cold.confirmed_committed_head_v0()
                .unwrap()
                .block_id()
                .as_bytes(),
            &c22_block
        );
    }
}
