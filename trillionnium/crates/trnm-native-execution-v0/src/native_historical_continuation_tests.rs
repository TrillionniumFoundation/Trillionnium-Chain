// M08-REPLAY-EXECUTION-V1 acceptance uses an independently constructed sender
// and the actual receiver cut captured before any C21 preparation.

fn historical_continuation_preview_request(
    template: &NativeBlockExecutionRequestV0,
    parent: &trnm_native_application::ApplicationHeadV0,
    transactions: Vec<Vec<u8>>,
) -> NativeBlockPreviewRequestV0 {
    NativeBlockPreviewRequestV0::new(
        template.chain_id().clone(),
        template.genesis_hash(),
        parent.clone(),
        template.height(),
        template.timestamp_ms(),
        template.active_validator_set_id(),
        transactions,
    )
    .unwrap()
}

fn historical_continuation_request(
    template: &NativeBlockExecutionRequestV0,
    parent: &trnm_native_application::ApplicationHeadV0,
) -> NativeBlockExecutionRequestV0 {
    NativeBlockExecutionRequestV0::new(
        template.chain_id().clone(),
        template.genesis_hash(),
        parent.clone(),
        template.block_id(),
        template.height(),
        template.timestamp_ms(),
        template.active_validator_set_id(),
        template.transactions().to_vec(),
        template.expected(),
    )
    .unwrap()
}

fn historical_continuation_counts(path: &std::path::Path) -> (u64, i64, i64) {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let sequence: Vec<u8> = connection
        .query_row(
            "SELECT durable_sequence FROM native_application_metadata_v0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let counts = connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM native_replay_execution_p_v1),
                    (SELECT COUNT(*) FROM native_replay_execution_finality_v1)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    (
        u64::from_be_bytes(sequence.try_into().unwrap()),
        counts.0,
        counts.1,
    )
}

fn assert_historical_continuation_replay_rejected(
    owner: &DurableNativeApplicationV0,
    parent: &trnm_native_application::ApplicationHeadV0,
    template: &NativeBlockExecutionRequestV0,
) {
    // Re-sign valid envelopes so command-ID and signer-nonce rejection are
    // exercised separately, on both sides of the receiver's original C18 cut.
    for (command_id, nonce, expected) in [
        ("native-history-prefix-1", 5, "command ID already committed"),
        ("native-history-suffix-2", 5, "command ID already committed"),
        (
            "native-history-new-id-for-nonce-1",
            1,
            "signer nonce already committed",
        ),
        (
            "native-history-new-id-for-nonce-2",
            2,
            "signer nonce already committed",
        ),
    ] {
        let transaction = signed_historical_runtime_transaction(
            command_id,
            nonce,
            trnm_protocol::CanonicalCommandV1::Transfer {
                to: "did:history:recipient".into(),
                amount: 1,
            },
        );
        let request = historical_continuation_preview_request(template, parent, vec![transaction]);
        let error = owner
            .preview_replay_block_v1(&request)
            .expect_err("an authentic historical replay identity cannot be reused");
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }
}

fn assert_historical_continuation_original_proof(
    path: &std::path::Path,
    block_id: [u8; 32],
    p_digest: [u8; 32],
    commit_sequence: u64,
    proof: &[u8],
) {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let (retained_p, retained_sequence, retained): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT p_digest,commit_sequence,proof FROM native_replay_execution_finality_v1 WHERE block_id=?1",
            [block_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(retained_p, p_digest);
    assert_eq!(retained_sequence, commit_sequence.to_be_bytes());
    assert_eq!(retained, proof);
}

fn assert_historical_continuation_uncertain(error: anyhow::Error, field: &str) {
    use crate::{NativeApplicationExecutionErrorCodeV0, NativeApplicationExecutionErrorV0};
    let error = error
        .downcast_ref::<NativeApplicationExecutionErrorV0>()
        .expect("continuation fsync must preserve its structured uncertainty error");
    assert_eq!(
        error.code(),
        NativeApplicationExecutionErrorCodeV0::CommitUncertain
    );
    assert_eq!(error.field(), field);
}

fn assert_historical_continuation_physical_head(
    path: &std::path::Path,
    head: &trnm_native_application::ApplicationHeadV0,
    sequence: u64,
) {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let matches: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM native_application_metadata_v0 WHERE singleton=1
         AND schema_version=?1 AND durable_sequence=?2 AND head_height=?3 AND head_block_id=?4
         AND head_state_root=?5 AND head_commit_id=?6)",
            rusqlite::params![
                12_u64.to_be_bytes().as_slice(),
                sequence.to_be_bytes().as_slice(),
                head.height().get().to_be_bytes().as_slice(),
                head.block_id().as_bytes().as_slice(),
                head.state_root().as_bytes().as_slice(),
                head.commit_id().as_bytes().as_slice(),
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        matches,
        "an uncertain post-COMMIT fence must retain the exact physical C33 head"
    );
}

fn assert_historical_continuation_pending_parent(
    path: &std::path::Path,
    block_id: [u8; 32],
    p_digest: [u8; 32],
    p_sequence: u64,
    parent_p_digest: [u8; 32],
) {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let matches: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM native_replay_execution_p_v1 WHERE block_id=?1
         AND p_digest=?2 AND p_sequence=?3 AND parent_kind=1 AND parent_p_digest=?4
         AND status=0 AND commit_sequence IS NULL AND commit_id IS NULL)",
            rusqlite::params![
                block_id.as_slice(),
                p_digest.as_slice(),
                p_sequence.to_be_bytes().as_slice(),
                parent_p_digest.as_slice()
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        matches,
        "C34 must retain its exact Prepared C33 parent and pending identity"
    );
}

// Rehash all untrusted local envelopes after changing an execution component.
// The genuine consensus header and its original proof are deliberately kept.
// A cold owner must derive the actual execution again, rather than accepting
// mutually consistent local hashes as execution authority.
fn rehash_historical_continuation_component(connection: &rusqlite::Connection, component: &str) {
    use trnm_finality_types::hash_domain;
    let (column, digest_column, metadata_column) = match component {
        "snapshot" => ("snapshot", "snapshot_digest", "authenticated_snapshot"),
        "commands" => ("commands", "commands_digest", "replay_command_ids"),
        "nonces" => ("nonces", "nonces_digest", "replay_signer_nonces"),
        _ => unreachable!(),
    };
    let original: Vec<u8> = connection
        .query_row(
            &format!("SELECT {column} FROM native_replay_execution_p_v1"),
            [],
            |row| row.get(0),
        )
        .unwrap();
    let bytes = match component {
        "snapshot" => {
            let mut bytes = original;
            // The final fixed-width JMT root remains canonically encoded.
            *bytes.last_mut().unwrap() ^= 1;
            bytes
        }
        "commands" => {
            let mut commands: std::collections::BTreeSet<String> =
                borsh::from_slice(&original).unwrap();
            assert!(commands.remove("native-history-prefix-1"));
            borsh::to_vec(&commands).unwrap()
        }
        "nonces" => {
            let mut nonces: std::collections::BTreeSet<(String, u64)> =
                borsh::from_slice(&original).unwrap();
            assert!(nonces.remove(&("did:operator:1".into(), 2)));
            borsh::to_vec(&nonces).unwrap()
        }
        _ => unreachable!(),
    };
    let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    connection
        .execute(
            &format!("UPDATE native_replay_execution_p_v1 SET {column}=?1,{digest_column}=?2"),
            rusqlite::params![bytes, digest.as_slice()],
        )
        .unwrap();
    connection
        .execute(
            &format!("UPDATE native_application_metadata_v0 SET {metadata_column}=?1"),
            [&bytes],
        )
        .unwrap();
    if component == "snapshot" {
        connection
            .execute(
                "UPDATE native_application_metadata_v0 SET authenticated_snapshot_digest=?1",
                [digest.as_slice()],
            )
            .unwrap();
    }
    let fields: Vec<Vec<u8>> = connection
        .query_row(
            "SELECT base_digest,p_sequence,parent_head,header,artifact,snapshot,commands,nonces,lifecycle,
                    block_id,commit_sequence FROM native_replay_execution_p_v1",
            [],
            |row| (0..11).map(|index| row.get(index)).collect(),
        )
        .unwrap();
    let (parent_kind, parent_p): (i64, Option<Vec<u8>>) = connection
        .query_row(
            "SELECT parent_kind,parent_p_digest FROM native_replay_execution_p_v1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(parent_kind, 0);
    assert!(parent_p.is_none());
    let component_digests: Vec<[u8; 32]> = fields[3..9]
        .iter()
        .map(|bytes| sha2::Sha256::digest(bytes).into())
        .collect();
    let mut parts: Vec<&[u8]> = vec![&fields[0], &fields[1], &[0], &fields[2], &[0]];
    parts.extend(component_digests.iter().map(|digest| digest.as_slice()));
    let p_digest = hash_domain("trnm.native.replay-execution-p.v1", &parts);
    let commit_id = hash_domain(
        "trnm.native.replay-execution-commit.v1",
        &[&fields[0], &p_digest, &fields[9], &component_digests[2]],
    );
    let proof_digest: Vec<u8> = connection
        .query_row(
            "SELECT proof_digest FROM native_replay_execution_finality_v1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let record_digest = hash_domain(
        "trnm.native.replay-execution-finality.v1",
        &[
            &fields[0],
            &fields[9],
            &p_digest,
            &fields[10],
            &proof_digest,
        ],
    );
    connection
        .execute(
            "UPDATE native_replay_execution_p_v1 SET p_digest=?1,commit_id=?2",
            rusqlite::params![p_digest.as_slice(), commit_id.as_slice()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE native_replay_execution_finality_v1 SET p_digest=?1,record_digest=?2",
            rusqlite::params![p_digest.as_slice(), record_digest.as_slice()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE native_application_metadata_v0 SET head_commit_id=?1",
            [commit_id.as_slice()],
        )
        .unwrap();
}

#[test]
fn historical_receiver_c33_executes_original_body_and_finality_after_cold_prepare() {
    use trnm_consensus_types::Cev0AdmissionBudgetV0;
    let directory = tempfile::tempdir().unwrap();
    let sender_path = directory.path().join("c33-sender.sqlite3");
    let receiver_path = directory.path().join("c33-receiver.sqlite3");
    let prepared_cold_path = directory.path().join("c33-prepared-cold.sqlite3");
    let fresh = vec![signed_historical_runtime_transaction(
        "native-history-c33-4",
        4,
        trnm_protocol::CanonicalCommandV1::Transfer {
            to: "did:history:recipient".into(),
            amount: 23,
        },
    )];
    let mut fixture = build_nonempty_historical_replay_fixture_with_continuation(
        &sender_path,
        &receiver_path,
        &fresh,
    );
    let c33 = commit_genuine_c33_continuation(&sender_path, fixture.continuation.take().unwrap());
    assert_eq!(c33.sender_request.transactions(), fresh);
    let sender_state = historical_fixture_state(&sender_path);
    assert!(sender_state.commands.contains("native-history-c33-4"));
    assert!(sender_state.nonces.contains(&("did:operator:1".into(), 4)));
    assert_eq!(sender_state.sequence, c33.commit_sequence);
    let source_rows = historical_retained_rows(&receiver_path);
    let journal_path =
        crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&receiver_path);
    let source_journal = std::fs::read(&journal_path).unwrap();
    let owner =
        DurableNativeApplicationV0::open(&receiver_path, native_checkpoint_fixture_config_v1())
            .unwrap();
    let anchor = owner
        .confirm_historical_replay_anchor_v1(
            &fixture.source_head,
            fixture.source_state.sequence,
            &fixture.source_header,
        )
        .unwrap();
    let base = owner
        .prepare_historical_replay_base_v1(
            &anchor,
            &fixture.history,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let installed = owner.install_historical_replay_base_v1(&base).unwrap();
    let local_c32 = installed.target_head().clone();
    let install_sequence = installed.install_sequence();
    let input_digest = installed.input_digest();
    let base_digest = installed.base_digest();
    assert_eq!(owner.confirmed_replay_head_v1().unwrap(), local_c32);
    assert_eq!(local_c32.block_id(), fixture.target_head.block_id());
    assert_eq!(local_c32.state_root(), fixture.target_head.state_root());
    assert_ne!(local_c32.commit_id(), fixture.target_head.commit_id());
    assert_eq!(
        historical_continuation_counts(&receiver_path),
        (install_sequence, 0, 0)
    );
    let before_rejections = std::fs::read(&receiver_path).unwrap();
    assert!(
        owner
            .prepare_replay_execution_v1(&c33.sender_request, &c33.header)
            .is_err(),
        "the sender's local C32 commit ID is not receiver parent authority"
    );
    assert_historical_continuation_replay_rejected(&owner, &local_c32, &c33.sender_request);
    assert_eq!(std::fs::read(&receiver_path).unwrap(), before_rejections);
    let request = historical_continuation_request(&c33.sender_request, &local_c32);
    let preview = owner
        .preview_replay_block_v1(&historical_continuation_preview_request(
            &request, &local_c32, fresh,
        ))
        .unwrap();
    assert_eq!(
        preview.payload_root().as_bytes(),
        c33.header.payload_root().as_bytes()
    );
    assert_eq!(
        preview.post_state_root().as_bytes(),
        c33.header.state_root().as_bytes()
    );
    assert_eq!(
        preview.receipts_root().as_bytes(),
        c33.header.receipts_root().as_bytes()
    );
    assert_eq!(
        preview.evidence_root().as_bytes(),
        c33.header.evidence_root().as_bytes()
    );
    let prepared = owner
        .prepare_replay_execution_v1(&request, &c33.header)
        .unwrap();
    assert!(prepared.belongs_to_application(&owner));
    let block_id = prepared.block_id();
    let p_digest = prepared.p_digest();
    let p_sequence = prepared.p_sequence();
    let prospective_head = prepared.target_head().clone();
    assert_eq!(block_id, *c33.header.id().as_bytes());
    assert_eq!(p_sequence, install_sequence + 1);
    assert_eq!(prospective_head.block_id(), c33.sender_head.block_id());
    assert_eq!(prospective_head.state_root(), c33.sender_head.state_root());
    assert_ne!(prospective_head.commit_id(), c33.sender_head.commit_id());
    assert_eq!(owner.confirmed_replay_head_v1().unwrap(), local_c32);
    let prepare_retry = owner
        .prepare_replay_execution_v1(&request, &c33.header)
        .unwrap();
    assert_eq!(prepare_retry.p_digest(), p_digest);
    assert_eq!(prepare_retry.p_sequence(), p_sequence);
    assert_eq!(
        historical_continuation_counts(&receiver_path),
        (p_sequence, 1, 0)
    );
    copy_later_store(&receiver_path, &prepared_cold_path);
    let (c34_block_id, c34_p_digest, c34_head) = {
        let source = rusqlite::Connection::open_with_flags(
            &sender_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let (artifact, header): (Vec<u8>, Vec<u8>) = source.query_row(
            "SELECT artifact,header FROM native_durable_execution_p_v1 WHERE target_height=?1 AND status=0",
            [34_u64.to_be_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        let executed =
            trnm_native_application::decode_native_executed_block_artifact_v0(&artifact).unwrap();
        let header = trnm_consensus_types::decode_block_header_v0_exact(&header).unwrap();
        assert_eq!(header.height().get(), 34);
        assert_eq!(header.parent_id(), c33.header.id());
        let branch = DurableNativeApplicationV0::open_historical_replay_v1(
            &prepared_cold_path,
            native_checkpoint_fixture_config_v1(),
        )
        .unwrap();
        let request = historical_continuation_request(executed.request(), &prospective_head);
        let p34 = branch
            .prepare_replay_execution_v1(&request, &header)
            .unwrap();
        assert_eq!(p34.p_sequence(), p_sequence + 1);
        assert_eq!(p34.target_head().height().get(), 34);
        assert_eq!(
            p34.target_head().block_id().as_bytes(),
            header.id().as_bytes()
        );
        assert_eq!(
            p34.target_head().state_root().as_bytes(),
            header.state_root().as_bytes()
        );
        assert_eq!(branch.confirmed_replay_head_v1().unwrap(), local_c32);
        assert_historical_continuation_pending_parent(
            &prepared_cold_path,
            p34.block_id(),
            p34.p_digest(),
            p34.p_sequence(),
            p_digest,
        );
        (p34.block_id(), p34.p_digest(), p34.target_head().clone())
    };
    let cold_prepared = DurableNativeApplicationV0::open_historical_replay_v1(
        &prepared_cold_path,
        native_checkpoint_fixture_config_v1(),
    )
    .unwrap();
    assert!(!prepared.belongs_to_application(&cold_prepared));
    assert!(cold_prepared
        .reopen_prepared_replay_execution_v1(block_id, [0; 32])
        .is_err());
    let before_reopen_fence = std::fs::read(&prepared_cold_path).unwrap();
    let fault = crate::durable::arm_sync_store_commit_boundary_fault_v0(
        cold_prepared.path(),
        crate::durable::SyncStoreCommitBoundaryFaultPointV0::Directory,
    );
    let error = cold_prepared
        .reopen_prepared_replay_execution_v1(block_id, p_digest)
        .err()
        .expect("cold Prepared recovery must reestablish the directory fence");
    assert_historical_continuation_uncertain(error, "replay.reopen_directory_fsync");
    drop(fault);
    assert_eq!(
        std::fs::read(&prepared_cold_path).unwrap(),
        before_reopen_fence
    );
    assert_eq!(
        historical_continuation_counts(&prepared_cold_path),
        (p_sequence + 1, 2, 0)
    );
    let reopened = cold_prepared
        .reopen_prepared_replay_execution_v1(block_id, p_digest)
        .unwrap();
    assert!(reopened.belongs_to_application(&cold_prepared));
    assert_eq!(reopened.p_sequence(), p_sequence);
    assert_eq!(reopened.target_head(), &prospective_head);
    assert_eq!(cold_prepared.confirmed_replay_head_v1().unwrap(), local_c32);
    let reopened_c34 = cold_prepared
        .reopen_prepared_replay_execution_v1(c34_block_id, c34_p_digest)
        .unwrap();
    assert_eq!(reopened_c34.p_sequence(), p_sequence + 1);
    assert_eq!(reopened_c34.target_head(), &c34_head);
    assert_historical_continuation_pending_parent(
        &prepared_cold_path,
        c34_block_id,
        c34_p_digest,
        p_sequence + 1,
        p_digest,
    );
    assert!(
        cold_prepared
            .commit_replay_finality_bytes_v1(
                &reopened,
                &fixture.history.terminal_finality_cev0,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .is_err(),
        "an original C32 proof cannot commit Prepared C33"
    );
    assert_eq!(
        historical_continuation_counts(&prepared_cold_path),
        (p_sequence + 1, 2, 0)
    );
    let cold_committed = cold_prepared
        .commit_replay_finality_bytes_v1(
            &reopened,
            &c33.original_finality_cev0,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(cold_committed.head(), &prospective_head);
    assert_eq!(cold_committed.p_digest(), p_digest);
    assert_eq!(cold_committed.commit_sequence(), p_sequence + 2);
    assert_eq!(
        historical_continuation_counts(&prepared_cold_path),
        (p_sequence + 2, 2, 1)
    );
    assert_eq!(
        cold_prepared.confirmed_replay_head_v1().unwrap(),
        prospective_head
    );
    let still_pending = cold_prepared
        .reopen_prepared_replay_execution_v1(c34_block_id, c34_p_digest)
        .unwrap();
    assert_eq!(still_pending.p_digest(), c34_p_digest);
    assert_eq!(still_pending.p_sequence(), p_sequence + 1);
    assert_eq!(still_pending.target_head(), &c34_head);
    assert_historical_continuation_pending_parent(
        &prepared_cold_path,
        c34_block_id,
        c34_p_digest,
        p_sequence + 1,
        p_digest,
    );
    drop(cold_prepared);
    // The first fault follows actual COMMIT. The second is an exact retry and
    // must repeat the fence without allocating another P or commit sequence.
    for _ in 0..2 {
        let fault = crate::durable::arm_sync_store_commit_boundary_fault_v0(
            owner.path(),
            crate::durable::SyncStoreCommitBoundaryFaultPointV0::Database,
        );
        let error = owner
            .commit_replay_finality_bytes_v1(
                &prepared,
                &c33.original_finality_cev0,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .err()
            .expect("a failed commit fence must not produce a committed receipt");
        assert_historical_continuation_uncertain(error, "replay.commit_fsync");
        drop(fault);
        assert_eq!(
            historical_continuation_counts(&receiver_path),
            (p_sequence + 1, 1, 1)
        );
        assert_historical_continuation_physical_head(
            &receiver_path,
            &prospective_head,
            p_sequence + 1,
        );
        assert_historical_continuation_original_proof(
            &receiver_path,
            block_id,
            p_digest,
            p_sequence + 1,
            &c33.original_finality_cev0,
        );
        let uncertain_state = historical_fixture_state(&receiver_path);
        assert_eq!(uncertain_state.snapshot, sender_state.snapshot);
        assert_eq!(uncertain_state.commands, sender_state.commands);
        assert_eq!(uncertain_state.nonces, sender_state.nonces);
    }
    let committed = owner
        .commit_replay_finality_bytes_v1(
            &prepared,
            &c33.original_finality_cev0,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let commit_sequence = committed.commit_sequence();
    assert_eq!(committed.head(), &prospective_head);
    assert_eq!(committed.p_digest(), p_digest);
    assert_eq!(commit_sequence, p_sequence + 1);
    assert_eq!(
        historical_continuation_counts(&receiver_path),
        (commit_sequence, 1, 1)
    );
    let current = historical_fixture_state(&receiver_path);
    assert_eq!(current.snapshot, sender_state.snapshot);
    assert_eq!(current.commands, sender_state.commands);
    assert_eq!(current.nonces, sender_state.nonces);
    let branch_state = historical_fixture_state(&prepared_cold_path);
    assert_eq!(branch_state.sequence, current.sequence + 1);
    assert_eq!(branch_state.snapshot, current.snapshot);
    assert_eq!(branch_state.commands, current.commands);
    assert_eq!(branch_state.nonces, current.nonces);
    let base_retry = owner.install_historical_replay_base_v1(&base).unwrap();
    assert_eq!(base_retry.base_digest(), base_digest);
    assert_eq!(base_retry.target_head(), &local_c32);
    assert_eq!(base_retry.install_sequence(), install_sequence);
    assert_eq!(owner.confirmed_replay_head_v1().unwrap(), prospective_head);
    assert_eq!(historical_fixture_state(&receiver_path), current);
    assert_eq!(historical_retained_rows(&receiver_path), source_rows);
    assert_eq!(std::fs::read(&journal_path).unwrap(), source_journal);
    drop(owner);
    let cold = DurableNativeApplicationV0::open_historical_replay_v1(
        &receiver_path,
        native_checkpoint_fixture_config_v1(),
    )
    .unwrap();
    assert_eq!(cold.confirmed_replay_head_v1().unwrap(), prospective_head);
    assert!(!prepared.belongs_to_application(&cold));
    let reopened = cold
        .reopen_prepared_replay_execution_v1(block_id, p_digest)
        .unwrap();
    let retry = cold
        .commit_replay_finality_bytes_v1(
            &reopened,
            &c33.original_finality_cev0,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(retry.head(), &prospective_head);
    assert_eq!(retry.commit_sequence(), commit_sequence);
    assert_eq!(retry.p_digest(), p_digest);
    let confirmed_base = cold
        .confirm_historical_replay_base_v1(input_digest, &local_c32)
        .unwrap();
    assert_eq!(confirmed_base.base_digest(), base_digest);
    assert_eq!(confirmed_base.install_sequence(), install_sequence);
    assert_eq!(cold.confirmed_replay_head_v1().unwrap(), prospective_head);
    assert!(cold.install_historical_replay_base_v1(&base).is_err());
    assert_eq!(historical_fixture_state(&receiver_path), current);
    assert_historical_continuation_original_proof(
        &receiver_path,
        block_id,
        p_digest,
        commit_sequence,
        &c33.original_finality_cev0,
    );
    drop(cold);
    for mutation in ["proof_deleted", "snapshot", "commands", "nonces"] {
        let path = directory
            .path()
            .join(format!("c33-mutant-{mutation}.sqlite3"));
        copy_later_store(&receiver_path, &path);
        let owner = DurableNativeApplicationV0::open_historical_replay_v1(
            &path,
            native_checkpoint_fixture_config_v1(),
        )
        .unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        if mutation == "proof_deleted" {
            connection
                .execute("DELETE FROM native_replay_execution_finality_v1", [])
                .unwrap();
        } else {
            rehash_historical_continuation_component(&connection, mutation);
        }
        drop(connection);
        let error = owner
            .confirm_historical_replay_base_v1(input_digest, &local_c32)
            .err()
            .expect("a fresh audit must reject the mutated continuation");
        let expected = if mutation == "proof_deleted" {
            "replay committed P lacks original proof"
        } else {
            "replay P differs from independent execution"
        };
        assert!(
            format!("{error:#}").contains(expected),
            "{mutation} must reach its specific audit check: {error:#}"
        );
        drop(owner);
        assert!(
            DurableNativeApplicationV0::open_historical_replay_v1(
                &path,
                native_checkpoint_fixture_config_v1(),
            )
            .is_err(),
            "cold continuation must reject {mutation}"
        );
    }
    assert_eq!(historical_retained_rows(&receiver_path), source_rows);
    assert_eq!(std::fs::read(&journal_path).unwrap(), source_journal);
    let connection = rusqlite::Connection::open_with_flags(
        &receiver_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let phase: (i64, Option<Vec<u8>>, Option<Vec<u8>>) = connection.query_row(
        "SELECT phase,consumed_block,consumed_sequence FROM native_later_epoch_edge_v1 WHERE checkpoint_block=?1",
        [fixture.source_header.id().as_bytes().as_slice()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).unwrap();
    assert_eq!(
        phase,
        (0, None, None),
        "continuation must not consume source C18 B"
    );
}
