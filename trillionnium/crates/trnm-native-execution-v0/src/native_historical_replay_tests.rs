// M06-HISTORY-EXEC-V1 fixture inputs. This first stage creates genuine local
// receiver state before the sender continues; it does not implement an import.

fn signed_historical_runtime_transaction(
    command_id: &str,
    nonce: u64,
    command: trnm_protocol::CanonicalCommandV1,
) -> Vec<u8> {
    let config = native_checkpoint_fixture_config_v1();
    let transaction = trnm_protocol::CanonicalTxV1 {
        schema: trnm_protocol::CANONICAL_TX_SCHEMA_V1.into(),
        sender: "did:operator:1".into(),
        nonce,
        max_gas: 100_000,
        fee_limit: 100_000,
        command,
    };
    let envelope = trnm_finality_types::SignedCommandEnvelopeV1::sign(
        config.chain_id_v0(),
        command_id,
        "did:operator:1",
        "operator",
        nonce,
        1_000,
        100_000,
        trnm_protocol::CANONICAL_TX_PAYLOAD_TYPE_V1,
        &serde_json::to_vec(&transaction).unwrap(),
        &ed25519_dalek::SigningKey::from_bytes(&[81; 32]),
    )
    .unwrap();
    serde_json::to_vec(&envelope).unwrap()
}

#[derive(Debug, PartialEq, Eq)]
struct HistoricalFixtureState {
    sequence: u64,
    snapshot: Vec<u8>,
    commands: std::collections::BTreeSet<String>,
    nonces: std::collections::BTreeSet<(String, u64)>,
}

fn historical_fixture_state(path: &std::path::Path) -> HistoricalFixtureState {
    let sql =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let (sequence, snapshot, commands, nonces): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = sql.query_row(
        "SELECT durable_sequence,authenticated_snapshot,replay_command_ids,replay_signer_nonces FROM native_application_metadata_v0 WHERE singleton=1",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).unwrap();
    HistoricalFixtureState {
        sequence: u64::from_be_bytes(sequence.try_into().unwrap()),
        snapshot,
        commands: borsh::from_slice(&commands).unwrap(),
        nonces: borsh::from_slice(&nonces).unwrap(),
    }
}

fn assert_historical_receiver_c18(path: &std::path::Path, header: &BlockHeader) {
    let receiver =
        DurableNativeApplicationV0::open(path, native_checkpoint_fixture_config_v1()).unwrap();
    let head = receiver.confirmed_committed_head_v0().unwrap();
    assert_eq!(head.height().get(), 18);
    assert_eq!(head.block_id().as_bytes(), header.id().as_bytes());
    let sql =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let schema: Vec<u8> = sql
        .query_row(
            "SELECT schema_version FROM native_application_metadata_v0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(u64::from_be_bytes(schema.try_into().unwrap()), 10);
    let phase: (i64, Option<Vec<u8>>, Option<Vec<u8>>) = sql.query_row(
        "SELECT phase,consumed_block,consumed_sequence FROM native_later_epoch_edge_v1 WHERE checkpoint_block=?",
        [header.id().as_bytes().as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    ).unwrap();
    assert_eq!(phase, (0, None, None), "receiver B must remain Installed");
    let future: i64 = sql
        .query_row(
            "SELECT COUNT(*) FROM native_durable_execution_p_v1 WHERE target_height>?",
            [18_u64.to_be_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(future, 0, "receiver cut must precede every C21 preparation");
    let journal = rusqlite::Connection::open_with_flags(
        crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(path),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let future: i64 = journal
        .query_row(
            "SELECT COUNT(*) FROM preparations WHERE height_be>?",
            [18_u64.to_be_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        future, 0,
        "receiver cannot inherit later signing preparations"
    );
}

fn historical_live_account(bytes: &[u8], account: &str) -> Option<trnm_protocol::AccountV1> {
    let live = crate::NativeCurrentLiveExportV1::decode(bytes).unwrap();
    let key = crate::stored_object_key_v0(&trnm_protocol::account_key(account)).unwrap();
    live.entries
        .iter()
        .find(|entry| entry.key == key)
        .map(|entry| {
            let record = crate::AuthenticatedObjectRecordV0::decode(&entry.value).unwrap();
            assert_eq!(record.object_type(), trnm_protocol::ACCOUNT_OBJECT_TYPE_V1);
            serde_json::from_slice(record.value()).unwrap()
        })
}

struct NonemptyHistoricalReplayFixture {
    receiver_config: crate::NativeApplicationConfigV0,
    source_head: trnm_native_application::ApplicationHeadV0,
    source_header: BlockHeader,
    source_state: HistoricalFixtureState,
    target_head: trnm_native_application::ApplicationHeadV0,
    target_header: BlockHeader,
    target_state: HistoricalFixtureState,
    history: crate::NativeHistoricalReplayV1,
    prefix: Vec<Vec<u8>>,
    suffix: Vec<Vec<u8>>,
}

#[inline(never)]
fn build_nonempty_historical_replay_fixture(
    sender_path: &std::path::Path,
    receiver_path: &std::path::Path,
) -> Box<NonemptyHistoricalReplayFixture> {
    let prefix = vec![signed_historical_runtime_transaction(
        "native-history-prefix-1",
        1,
        trnm_protocol::CanonicalCommandV1::CreditAccount {
            account: "did:operator:1".into(),
            amount: 1_000_000,
        },
    )];
    let suffix = [41, 17]
        .into_iter()
        .enumerate()
        .map(|(index, amount)| {
            let nonce = index as u64 + 2;
            signed_historical_runtime_transaction(
                &format!("native-history-suffix-{nonce}"),
                nonce,
                trnm_protocol::CanonicalCommandV1::Transfer {
                    to: "did:history:recipient".into(),
                    amount,
                },
            )
        })
        .collect::<Vec<_>>();
    let seed =
        build_later_descendant_fixture_with_transactions(sender_path, &prefix, Some(receiver_path));
    let source_header = seed.checkpoint_header.clone();
    let receiver =
        DurableNativeApplicationV0::open(receiver_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    let source_head = receiver.confirmed_committed_head_v0().unwrap();
    let source_state = historical_fixture_state(receiver_path);
    let source_preparations = std::fs::read(
        crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(receiver_path),
    )
    .unwrap();
    let source_database = std::fs::read(receiver_path).unwrap();
    drop(receiver);
    let checkpoint = advance_repeated_checkpoint_with_transactions(seed, &suffix);
    complete_repeated_handoff(sender_path, checkpoint);
    assert_historical_receiver_c18(receiver_path, &source_header);
    assert_eq!(historical_fixture_state(receiver_path), source_state);
    assert_eq!(std::fs::read(receiver_path).unwrap(), source_database);
    assert_eq!(
        std::fs::read(
            crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(receiver_path)
        )
        .unwrap(),
        source_preparations
    );
    let sender =
        DurableNativeApplicationV0::open(sender_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    let target_head = sender.confirmed_committed_head_v0().unwrap();
    let history = sender
        .export_historical_replay_v1(source_head.block_id(), target_head.block_id())
        .unwrap();
    let target_header = trnm_consensus_types::decode_block_header_v0_exact(
        history.records.last().unwrap().header_cev0(),
    )
    .unwrap();
    let target_state = historical_fixture_state(sender_path);
    Box::new(NonemptyHistoricalReplayFixture {
        receiver_config: native_checkpoint_fixture_config_v1(),
        source_head,
        source_header,
        source_state,
        target_head,
        target_header,
        target_state,
        history,
        prefix,
        suffix,
    })
}

#[test]
fn nonempty_historical_fixture_captures_c18_before_c21_and_exports_exact_payloads() {
    let directory = tempfile::tempdir().unwrap();
    let sender_path = directory.path().join("nonempty-sender.sqlite3");
    let receiver_path = directory.path().join("local-receiver-c18.sqlite3");
    let fixture = build_nonempty_historical_replay_fixture(&sender_path, &receiver_path);
    assert_eq!(
        fixture.receiver_config.store_id(),
        native_checkpoint_fixture_config_v1().store_id()
    );
    assert_eq!(fixture.source_header.height().get(), 18);
    assert_eq!(
        fixture.source_head.block_id().as_bytes(),
        fixture.source_header.id().as_bytes()
    );
    assert_eq!(fixture.target_header.height().get(), 32);
    assert_eq!(
        fixture.target_head.block_id().as_bytes(),
        fixture.target_header.id().as_bytes()
    );
    assert!(fixture.target_state.sequence > fixture.source_state.sequence);
    assert_eq!(
        fixture.source_state.commands,
        std::collections::BTreeSet::from(["native-history-prefix-1".to_owned()])
    );
    assert_eq!(
        fixture.source_state.nonces,
        std::collections::BTreeSet::from([("did:operator:1".to_owned(), 1)])
    );
    assert_eq!(
        fixture.target_state.commands,
        std::collections::BTreeSet::from([
            "native-history-prefix-1".to_owned(),
            "native-history-suffix-2".to_owned(),
            "native-history-suffix-3".to_owned(),
        ])
    );
    assert_eq!(
        fixture.target_state.nonces,
        (1..=3)
            .map(|nonce| ("did:operator:1".to_owned(), nonce))
            .collect()
    );

    let sender =
        DurableNativeApplicationV0::open(&sender_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    let prefix_read = sender
        .read_finalized_by_height_v1(HeightV0::new(12))
        .unwrap();
    assert_eq!(
        prefix_read.executed_v1().request().transactions(),
        fixture.prefix
    );
    let mut nonempty = Vec::new();
    for record in &fixture.history.records {
        if let crate::NativeHistoricalRecordV1::Application {
            header_cev0,
            application_payload_cev0,
        } = record
        {
            let header = trnm_consensus_types::decode_block_header_v0_exact(header_cev0).unwrap();
            let payload = trnm_consensus_types::decode_application_payload_v0_exact(
                application_payload_cev0,
                fixture.receiver_config.consensus_parameters_v0(),
            )
            .unwrap();
            assert_eq!(payload.payload_root().unwrap(), header.payload_root());
            if !payload.transactions().is_empty() {
                nonempty.push((header.height().get(), payload.transactions().to_vec()));
            }
        }
    }
    assert_eq!(nonempty, vec![(25, fixture.suffix.clone())]);
    let live = sender
        .export_current_native_live_v1(fixture.target_head.block_id())
        .unwrap();
    assert_eq!(
        historical_live_account(&live, "did:history:recipient")
            .unwrap()
            .balance,
        58
    );
    assert_eq!(
        historical_live_account(&live, "did:operator:1")
            .unwrap()
            .nonce,
        3
    );
    drop(sender);
    let cold =
        DurableNativeApplicationV0::open(&sender_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    assert_eq!(
        cold.confirmed_committed_head_v0().unwrap(),
        fixture.target_head
    );
    assert_eq!(historical_fixture_state(&sender_path), fixture.target_state);
    assert_eq!(
        cold.export_current_native_live_v1(fixture.target_head.block_id())
            .unwrap(),
        live
    );
    assert_eq!(
        cold.export_historical_replay_v1(
            fixture.source_head.block_id(),
            fixture.target_head.block_id()
        )
        .unwrap(),
        fixture.history
    );
    assert_historical_receiver_c18(&receiver_path, &fixture.source_header);
    assert_receiver_historical_replay(&receiver_path, &fixture);
    assert_historical_receiver_inventory_pins(&receiver_path, &fixture);
}

#[inline(never)]
fn assert_receiver_historical_replay(
    receiver_path: &std::path::Path,
    fixture: &NonemptyHistoricalReplayFixture,
) {
    let receiver =
        DurableNativeApplicationV0::open(receiver_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    let before_database = std::fs::read(receiver_path).unwrap();
    let journal_path =
        crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(receiver_path);
    let before_journal = std::fs::read(&journal_path).unwrap();
    assert!(receiver
        .confirm_historical_replay_anchor_v1(
            &fixture.source_head,
            fixture.source_state.sequence + 1,
            &fixture.source_header,
        )
        .is_err());
    assert!(receiver
        .confirm_historical_replay_anchor_v1(
            &fixture.source_head,
            fixture.source_state.sequence,
            &fixture.target_header,
        )
        .is_err());
    let anchor = receiver
        .confirm_historical_replay_anchor_v1(
            &fixture.source_head,
            fixture.source_state.sequence,
            &fixture.source_header,
        )
        .unwrap();
    assert!(anchor.belongs_to_application(&receiver));
    assert_eq!(anchor.source_head(), &fixture.source_head);
    assert_eq!(anchor.source_sequence(), fixture.source_state.sequence);
    let other_directory = tempfile::tempdir().unwrap();
    let other_path = other_directory.path().join("foreign-owner-c18.sqlite3");
    copy_later_store(receiver_path, &other_path);
    let other_owner =
        DurableNativeApplicationV0::open(&other_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    assert!(!anchor.belongs_to_application(&other_owner));
    assert!(other_owner
        .prepare_historical_replay_base_v1(
            &anchor,
            &fixture.history,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err());
    drop(other_owner);

    let prepared = receiver
        .prepare_historical_replay_base_v1(
            &anchor,
            &fixture.history,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .expect("signed nonempty history must reexecute against the genuine local C18 source");
    assert!(prepared.belongs_to_application(&receiver));
    assert_eq!(prepared.source_head(), &fixture.source_head);
    assert_eq!(prepared.source_sequence(), fixture.source_state.sequence);
    assert_eq!(
        prepared.source_inventory_digest(),
        anchor.source_inventory_digest()
    );
    assert_eq!(prepared.application_count(), 10);
    assert_eq!(prepared.target_header(), &fixture.target_header);
    assert_eq!(
        prepared.target_head().height(),
        fixture.target_head.height()
    );
    assert_eq!(
        prepared.target_head().block_id(),
        fixture.target_head.block_id()
    );
    assert_eq!(
        prepared.target_head().state_root(),
        fixture.target_head.state_root()
    );
    assert_ne!(
        prepared.target_head().commit_id(),
        fixture.target_head.commit_id()
    );
    assert_eq!(
        prepared.target_validator_set().id(),
        fixture.target_header.validator_set_id()
    );
    assert_eq!(
        prepared.target_parameters().hash(),
        fixture.target_header.consensus_parameters_hash()
    );
    assert_eq!(
        prepared.history_byte_len(),
        fixture.history.encode_v1().unwrap().len()
    );
    let command_digest: [u8; 32] =
        sha2::Sha256::digest(borsh::to_vec(&fixture.target_state.commands).unwrap()).into();
    let nonce_digest: [u8; 32] =
        sha2::Sha256::digest(borsh::to_vec(&fixture.target_state.nonces).unwrap()).into();
    assert_eq!(prepared.command_replay_digest(), command_digest);
    assert_eq!(prepared.nonce_replay_digest(), nonce_digest);
    let repeated = receiver
        .prepare_historical_replay_base_v1(
            &anchor,
            &fixture.history,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(repeated.target_head(), prepared.target_head());
    assert_eq!(repeated.target_header(), prepared.target_header());
    assert_eq!(repeated.input_digest(), prepared.input_digest());
    assert_eq!(repeated.run_digest(), prepared.run_digest());
    assert_eq!(repeated.snapshot_digest(), prepared.snapshot_digest());
    assert_eq!(
        repeated.command_replay_digest(),
        prepared.command_replay_digest()
    );
    assert_eq!(
        repeated.nonce_replay_digest(),
        prepared.nonce_replay_digest()
    );
    assert_eq!(repeated.lifecycle_digest(), prepared.lifecycle_digest());
    assert_eq!(
        repeated.source_inventory_digest(),
        prepared.source_inventory_digest()
    );

    for mutation in [
        "seal_as_application",
        "application_as_seal",
        "payload_order",
    ] {
        let mut mutant = fixture.history.clone();
        match mutation {
            "seal_as_application" => {
                let first = &mut mutant.records[0];
                *first = crate::NativeHistoricalRecordV1::Application {
                    header_cev0: first.header_cev0().to_vec(),
                    application_payload_cev0: trnm_consensus_types::ApplicationPayloadV0::new(
                        Vec::new(),
                    )
                    .unwrap()
                    .try_cev0_bytes()
                    .unwrap(),
                };
            }
            "application_as_seal" => {
                let first_new = &mut mutant.records[2];
                *first_new = crate::NativeHistoricalRecordV1::Seal {
                    header_cev0: first_new.header_cev0().to_vec(),
                };
            }
            "payload_order" => {
                let mut reversed = fixture.suffix.clone();
                reversed.reverse();
                let crate::NativeHistoricalRecordV1::Application {
                    application_payload_cev0,
                    ..
                } = &mut mutant.records[6]
                else {
                    panic!("the height25 record must carry an application body");
                };
                *application_payload_cev0 =
                    trnm_consensus_types::ApplicationPayloadV0::new(reversed)
                        .unwrap()
                        .try_cev0_bytes()
                        .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            receiver
                .prepare_historical_replay_base_v1(
                    &anchor,
                    &mutant,
                    &mut Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .is_err(),
            "historical replay must reject {mutation}"
        );
    }
    assert_eq!(
        receiver.confirmed_committed_head_v0().unwrap(),
        fixture.source_head
    );
    assert_eq!(
        historical_fixture_state(receiver_path),
        fixture.source_state
    );
    assert_eq!(std::fs::read(receiver_path).unwrap(), before_database);
    assert_eq!(std::fs::read(journal_path).unwrap(), before_journal);
    drop(receiver);
    assert_historical_receiver_c18(receiver_path, &fixture.source_header);
}

#[inline(never)]
fn build_genuine_alternate_c8_preparation(
    source_path: &std::path::Path,
    branch_path: &std::path::Path,
) {
    use trnm_native_application::{
        NativeApplicationCommitRequestV0, NativeApplicationV0, NativeBlockExecutionResultV0,
    };
    let branch = crate::poco_checkpoint::native_checkpoint_fixture_v1::open_native_checkpoint_fixture_genesis_v1(branch_path);
    let config = native_checkpoint_fixture_config_v1();
    let source = rusqlite::Connection::open_with_flags(
        source_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut headers = Vec::new();
    for height in 1_u64..=7 {
        let artifact: Vec<u8> = source.query_row(
            "SELECT artifact FROM native_durable_execution_p_v0 WHERE target_height=? AND status=?",
            rusqlite::params![height.to_be_bytes().as_slice(), 2_u64.to_be_bytes().as_slice()],
            |row| row.get(0),
        ).unwrap();
        let original =
            trnm_native_application::decode_native_executed_block_artifact_v0(&artifact).unwrap();
        let request = original.request();
        let header = checkpoint_like_header_at_view(
            config.validator_set_v0(),
            BlockKind::Regular,
            height,
            BlockId::new(*request.parent().block_id().as_bytes()),
            StateRoot::new(*request.expected().post_state_root().as_bytes()),
            None,
            request.timestamp_ms(),
            PayloadDigest::new(*request.expected().payload_root().as_bytes()),
            ReceiptsRoot::new(*request.expected().receipts_root().as_bytes()),
            EvidenceRoot::new(*request.expected().evidence_root().as_bytes()),
            height,
        );
        assert_eq!(header.id().as_bytes(), request.block_id().as_bytes());
        let NativeBlockExecutionResultV0::Valid(executed) =
            branch.execute_block(request.clone()).unwrap()
        else {
            panic!("genuine local C8 branch must execute its original prefix");
        };
        branch
            .commit_block(NativeApplicationCommitRequestV0::new(*executed))
            .unwrap();
        headers.push(header);
    }
    let original_evidence: Vec<u8> = source
        .query_row(
            "SELECT evidence FROM native_epoch_edge_v1 WHERE checkpoint_height=?",
            [8_u64.to_be_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let original_evidence =
        crate::epoch_recovery::EpochRecoveryEvidenceV1::decode(&original_evidence).unwrap();
    assert_eq!(
        original_evidence.cutoff_parent,
        headers[3].try_cev0_bytes().unwrap()
    );
    // The transition pin includes the exact original cutoff proof. A freshly
    // signed valid proof with a different QC signer list has a different pin.
    let request = NativeBlockPreviewRequestV0::new(
        ChainIdV0::new(config.chain_id_v0()).unwrap(),
        GenesisHashV0::new([7; 32]).unwrap(),
        branch.confirmed_committed_head_v0().unwrap(),
        HeightV0::new(8),
        8_000,
        trnm_native_application::ValidatorSetIdV0::new(*config.validator_set_v0().id().as_bytes())
            .unwrap(),
        Vec::new(),
    )
    .unwrap();
    let prepared = branch
        .prepare_native_poco_checkpoint_v0(
            &request,
            View::new(12),
            config.validator_set_v0().validators()[3].id(),
            &original_evidence.cutoff_finality,
            &original_evidence.cutoff_parent,
        )
        .unwrap();
    assert_eq!(prepared.header().view(), View::new(12));
    assert_eq!(
        branch.confirmed_committed_head_v0().unwrap().height().get(),
        7
    );
}

#[inline(never)]
fn assert_historical_receiver_inventory_pins(
    receiver_path: &std::path::Path,
    fixture: &NonemptyHistoricalReplayFixture,
) {
    use crate::poco_preparation_journal::{
        poco_preparation_sidecar_path_v0, PocoPreparationJournalV0,
    };
    let directory = tempfile::tempdir().unwrap();
    let stale_path = directory.path().join("stale-local-c18.sqlite3");
    let missing_path = directory.path().join("missing-required-c8.sqlite3");
    let branch_path = directory.path().join("genuine-c8-view12.sqlite3");
    copy_later_store(receiver_path, &stale_path);
    copy_later_store(receiver_path, &missing_path);
    build_genuine_alternate_c8_preparation(receiver_path, &branch_path);
    let stale =
        DurableNativeApplicationV0::open(&stale_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    let anchor = stale
        .confirm_historical_replay_anchor_v1(
            &fixture.source_head,
            fixture.source_state.sequence,
            &fixture.source_header,
        )
        .unwrap();
    let before = historical_fixture_state(&stale_path);
    let database = std::fs::read(&stale_path).unwrap();
    let journal_path = poco_preparation_sidecar_path_v0(&stale_path);
    let journal = rusqlite::Connection::open(&journal_path).unwrap();
    journal
        .execute(
            "ATTACH DATABASE ? AS alternate",
            [poco_preparation_sidecar_path_v0(&branch_path)
                .to_str()
                .unwrap()],
        )
        .unwrap();
    let matching: bool = journal.query_row(
        "SELECT a.binding_record=b.binding_record AND a.binding_checksum=b.binding_checksum FROM transition_bindings a JOIN alternate.transition_bindings b USING(transition_key)",
        [], |row| row.get(0),
    ).unwrap();
    assert!(
        matching,
        "only an exact genuine transition binding may append a new view"
    );
    assert_eq!(journal.execute(
        "INSERT INTO preparations SELECT * FROM alternate.preparations WHERE height_be=?1 AND view_be=?2",
        rusqlite::params![8_u64.to_be_bytes().as_slice(),12_u64.to_be_bytes().as_slice()],
    ).unwrap(), 1);
    journal.execute_batch("DETACH DATABASE alternate").unwrap();
    drop(journal);
    let checked_journal = PocoPreparationJournalV0::open_existing(&journal_path).unwrap();
    assert_eq!(checked_journal.replay_records().unwrap().len(), 2);
    assert!(!checked_journal.is_halted().unwrap());
    let fresh_anchor = stale
        .confirm_historical_replay_anchor_v1(
            &fixture.source_head,
            fixture.source_state.sequence,
            &fixture.source_header,
        )
        .expect("a canonical extra old checkpoint view leaves the source otherwise valid");
    assert_ne!(
        fresh_anchor.source_inventory_digest(),
        anchor.source_inventory_digest()
    );
    let error = stale
        .prepare_historical_replay_base_v1(
            &anchor,
            &fixture.history,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .err()
        .expect("an earlier anchor must notice journal changes at an unchanged head");
    assert!(
        error.to_string().contains("historical anchor stale source"),
        "{error:#}"
    );
    assert_eq!(historical_fixture_state(&stale_path), before);
    assert_eq!(std::fs::read(&stale_path).unwrap(), database);

    let missing =
        DurableNativeApplicationV0::open(&missing_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    let database = std::fs::read(&missing_path).unwrap();
    let journal_path = poco_preparation_sidecar_path_v0(&missing_path);
    let journal = rusqlite::Connection::open(&journal_path).unwrap();
    assert_eq!(
        journal
            .execute(
                "DELETE FROM preparations WHERE height_be=?1 AND view_be=?2",
                rusqlite::params![
                    8_u64.to_be_bytes().as_slice(),
                    8_u64.to_be_bytes().as_slice()
                ],
            )
            .unwrap(),
        1
    );
    drop(journal);
    let checked_journal = PocoPreparationJournalV0::open_existing(&journal_path).unwrap();
    assert!(checked_journal.replay_records().unwrap().is_empty());
    assert!(!checked_journal.is_halted().unwrap());
    let error = missing
        .confirm_historical_replay_anchor_v1(
            &fixture.source_head,
            fixture.source_state.sequence,
            &fixture.source_header,
        )
        .err()
        .expect("missing required original C8 binding must fail despite a well-formed journal");
    assert!(
        error
            .to_string()
            .contains("historical legacy checkpoint lacks exact retained preparation",),
        "{error:#}",
    );
    assert_eq!(historical_fixture_state(&missing_path), before);
    assert_eq!(std::fs::read(&missing_path).unwrap(), database);
}
