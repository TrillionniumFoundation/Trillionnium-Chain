type PreHandoffCaseV5 = (
    tempfile::TempDir,
    super::EpochPreHandoffRuntimeV5<Watermark, Watermark>,
    Key,
);

#[inline(never)]
fn pre_handoff_begin_v5(case: Box<CheckpointCaseV4>) -> Box<PreHandoffCaseV5> {
    let (directory, owner, key) = *checkpoint_prepare_signed_v4(case);
    Box::new((directory, owner.into_pre_handoff_v5().unwrap(), key))
}

#[inline(never)]
fn genuine_seal_proposal_v5(
    owner: &super::EpochPreHandoffRuntimeV5<Watermark, Watermark>,
    nonempty: bool,
    wrong_state: bool,
) -> SignedProposalV0 {
    let inner = owner.inner.as_ref().unwrap();
    let checkpoint = inner.prepared.last().unwrap().prepared.header().unwrap();
    let parent = owner
        .seals
        .last()
        .map(|p| p.block().header())
        .unwrap_or(&checkpoint);
    let set = inner.runtime.edge.new_validator_set();
    let parameters = inner.runtime.edge.new_parameters();
    // Consensus transports transaction bytes opaquely. The negative is valid
    // CEV0 with one opaque transaction; a seal must reject any such payload.
    let payload = trnm_consensus_types::ApplicationPayloadV0::new(if nonempty {
        vec![b"opaque seal transaction must never execute".to_vec()]
    } else {
        Vec::new()
    })
    .unwrap();
    let view = View::new(parent.view().get() + 1);
    let proposer = trnm_consensus_core::leader_for(set, view);
    let empty_root = |kind| {
        trnm_consensus_types::OrderedRootV0::from_items::<&[u8]>(kind, &[])
            .unwrap()
            .digest()
    };
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        view,
        parent.height().checked_next().unwrap(),
        if owner.seals.is_empty() {
            BlockKind::EpochSeal1
        } else {
            BlockKind::EpochSeal2
        },
        parent.id(),
        proposer,
        set.id(),
        parameters.hash(),
        payload.payload_root().unwrap(),
        if wrong_state {
            StateRoot::new([0xd6; 32])
        } else {
            parent.state_root()
        },
        ReceiptsRoot::new(empty_root(trnm_consensus_types::RootKind::Receipts)),
        EvidenceRoot::new(empty_root(trnm_consensus_types::RootKind::Evidence)),
        parent.timestamp_ms() + 1,
        parent.next_epoch_commitment_hash(),
    )
    .unwrap();
    let justify = QcReferenceV0::ordinary(first_apply_qc_v2(parent, set));
    let root = ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
    let index = set
        .validators()
        .iter()
        .position(|v| v.id() == proposer)
        .unwrap();
    let signature = SigningKey::from_bytes(&[20 + index as u8; 32]).sign(root.as_bytes());
    let witness = ProposalWitnessV0::new(
        &header,
        justify,
        None,
        None,
        SignatureBytes::from_array(signature.to_bytes()),
        set,
        None,
        parameters,
        parent.timestamp_ms(),
    )
    .unwrap();
    let proposal = SignedProposalV0::new(
        Block::new(header, payload.try_cev0_bytes().unwrap(), Vec::new()).unwrap(),
        witness,
        set,
        None,
        parameters,
        parent.timestamp_ms(),
    )
    .unwrap();
    proposal
        .verify(
            set,
            None,
            parameters,
            parent.timestamp_ms(),
            &trnm_consensus_crypto::StrictEd25519Verifier,
        )
        .unwrap();
    proposal
}

#[inline(never)]
fn pre_handoff_pending_seal_vote_v5(case: Box<PreHandoffCaseV5>) -> Box<PreHandoffCaseV5> {
    let (directory, mut owner, key) = *case;
    let previous = owner
        .inner
        .as_ref()
        .unwrap()
        .runtime
        .checkpoint
        .fields()
        .application;
    let index = owner.seals.len();
    assert_eq!(previous.height, 15 + index as u64);
    let inner = owner.inner.as_ref().unwrap();
    let paths = [
        inner.runtime.application.path().to_path_buf(),
        inner.runtime.journal.path_v1().to_path_buf(),
        inner.runtime.ordinary.path().to_path_buf(),
        inner.runtime.checkpoint_store.database_path().to_path_buf(),
    ];
    let before: Vec<_> = paths.iter().map(|p| sqlite_logical_image_v3(p)).collect();
    let calls = key.calls;
    for (nonempty, wrong_state) in [(true, false), (false, true)] {
        let bad = genuine_seal_proposal_v5(&owner, nonempty, wrong_state);
        assert!(owner
            .admit_seal_proposal_v5(bad)
            .unwrap_err()
            .to_string()
            .contains("seal proposal semantics"));
        assert_eq!(key.calls, calls);
        for (path, original) in paths.iter().zip(&before) {
            assert!(
                sqlite_logical_image_v3(path) == *original,
                "rejected seal mutated {}",
                path.display()
            );
        }
    }
    let proposal = genuine_seal_proposal_v5(&owner, false, false);
    let seal_header = proposal.block().header().clone();
    owner.admit_seal_proposal_v5(proposal.clone()).unwrap();
    assert_eq!(key.calls, calls);
    assert!(owner.admit_seal_proposal_v5(proposal.clone()).is_err());
    let inner = owner.inner.as_ref().unwrap();
    assert!(inner.runtime.pending_epoch_commit.is_none());
    let state = inner.runtime.driver.state();
    assert_eq!(
        state
            .pending_finalization()
            .unwrap()
            .proof()
            .finalized_block()
            .header()
            .height()
            .get(),
        previous.height + 1
    );
    assert_eq!(state.application_applied().height().get(), previous.height);
    assert!(state.payload_terminal_fact(seal_header.id()).is_none());
    assert!(!state
        .payload_validation_completions()
        .iter()
        .any(|p| p.id().block_id() == seal_header.id()));
    assert_eq!(
        state
            .old_epoch_boundary_v1()
            .unwrap()
            .seals()
            .iter()
            .filter(|p| *p == &proposal)
            .count(),
        0,
        "original seal remains inert until the preceding application ACK"
    );
    assert!(state.pending_sign().is_none());
    let safety = inner
        .runtime
        .journal
        .fresh_read_v1(inner.runtime.pin)
        .unwrap();
    assert_eq!(safety.state_v1(), state);
    assert!(safety
        .transition_context_v1()
        .native_valid_transition()
        .is_none());
    let original_front = owner.inner.as_ref().unwrap().prepared[0]
        .prepared
        .p_digest();
    owner = owner
        .apply_preceding_application_v5(
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let inner = owner.inner.as_ref().unwrap();
    assert_eq!(
        inner.runtime.checkpoint.fields().application.height,
        previous.height + 1
    );
    assert_eq!(
        inner.runtime.checkpoint.fields().application.p_digest,
        original_front
    );
    assert_eq!(
        inner
            .runtime
            .application
            .confirmed_committed_head_v0()
            .unwrap()
            .height()
            .get(),
        previous.height + 1
    );
    assert_eq!(
        inner.runtime.driver.state().application_applied(),
        inner.runtime.driver.state().finalized()
    );
    assert!(inner.runtime.driver.state().pending_finalize().is_none());
    assert!(inner.runtime.driver.state().pending_sign().is_some());
    assert_eq!(key.calls, calls, "application ACK does not enter the key");
    assert_eq!(
        inner
            .runtime
            .driver
            .state()
            .old_epoch_boundary_v1()
            .unwrap()
            .seals()
            .iter()
            .filter(|p| *p == &proposal)
            .count(),
        1
    );
    let safety = inner
        .runtime
        .journal
        .fresh_read_v1(inner.runtime.pin)
        .unwrap();
    assert_eq!(safety.state_v1(), inner.runtime.driver.state());
    // Original seal admission is the newest ordinary transition. Its retained
    // predecessor is the actual native application receipt, not a synthetic tag.
    let journal = rusqlite::Connection::open_with_flags(
        &paths[1],
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let transition: Vec<u8> = journal
        .query_row(
            "SELECT transition FROM epoch_records ORDER BY revision DESC LIMIT 1 OFFSET 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        trnm_consensus_safety_store::decode_transition_context_v0_exact(&transition)
            .unwrap()
            .native_finalization_applied_transition()
            .is_some()
    );
    drop(journal);
    inner
        .runtime
        .journal
        .fresh_read_v1(inner.runtime.pin)
        .unwrap();
    let conn = rusqlite::Connection::open(&paths[0]).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM native_durable_execution_p_v1 WHERE block_id=?1",
            [seal_header.id().as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "seal must never manufacture native P");
    Box::new((directory, owner, key))
}

#[inline(never)]
fn pre_handoff_seal_and_apply_v5(case: Box<PreHandoffCaseV5>) -> Box<PreHandoffCaseV5> {
    let (directory, owner, mut key) = *pre_handoff_pending_seal_vote_v5(case);
    let seal_id = owner.seals.last().unwrap().block().id();
    let calls = key.calls;
    let (owner, vote) = owner.sign_seal_vote_v5(&mut key).unwrap();
    assert_eq!(key.calls, calls + 1);
    let trnm_consensus_core::OutboundMessage::Vote(vote) = vote else {
        panic!("real seal Vote required")
    };
    assert_eq!(vote.block_id(), seal_id);
    assert!(owner
        .inner
        .as_ref()
        .unwrap()
        .runtime
        .driver
        .state()
        .pending_sign()
        .is_none());
    Box::new((directory, owner, key))
}

#[inline(never)]
fn pre_handoff_commit_v5(case: Box<PreHandoffCaseV5>) -> Box<PreHandoffCaseV5> {
    let (directory, mut owner, key) = *case;
    assert!(owner.settled_pre_handoff_cut_v5().is_err());
    let inner = owner.inner.as_ref().unwrap();
    assert_eq!(inner.prepared.len(), 1);
    let checkpoint = inner.prepared[0].prepared.header().unwrap();
    let original_p = inner.prepared[0].prepared.p_digest();
    let terminal = owner.seals[1].block().header();
    let qc = first_apply_qc_v2(terminal, inner.runtime.edge.new_validator_set());
    let wrong_qc = first_apply_qc_v2(
        owner.seals[0].block().header(),
        inner.runtime.edge.new_validator_set(),
    );
    let path = inner.runtime.journal.path_v1().to_path_buf();
    let unchanged = sqlite_logical_image_v3(&path);
    assert!(owner
        .observe_terminal_qc_v5(wrong_qc)
        .unwrap_err()
        .to_string()
        .contains("terminal QC target"));
    assert!(sqlite_logical_image_v3(&path) == unchanged);
    owner.observe_terminal_qc_v5(qc).unwrap();
    let original_proof = owner
        .inner
        .as_ref()
        .unwrap()
        .runtime
        .driver
        .state()
        .pending_finalization()
        .unwrap()
        .proof()
        .try_cev0_bytes()
        .unwrap();
    let calls = key.calls;
    owner = owner
        .apply_pre_handoff_checkpoint_v5(
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    assert_eq!(
        key.calls, calls,
        "pre-handoff commit must not call either role signer"
    );
    let cut = owner.settled_pre_handoff_cut_v5().unwrap();
    assert_eq!(cut.fields().application.height, 18);
    assert_eq!(cut.fields().application.p_digest, original_p);
    let inner = owner.inner.as_ref().unwrap();
    let receipt = owner.receipt.as_ref().unwrap();
    assert_eq!(receipt.header(), &checkpoint);
    assert!(receipt.belongs_to_application(&inner.runtime.application));
    assert_eq!(
        receipt.commit_sequence(),
        cut.fields().application.commit_sequence
    );
    assert_eq!(
        inner
            .runtime
            .driver
            .state()
            .old_epoch_boundary_v1()
            .unwrap()
            .phase(inner.runtime.driver.state()),
        trnm_consensus_core::OldEpochBoundaryPhaseV1::CheckpointApplied
    );
    let conn = rusqlite::Connection::open(inner.runtime.application.path()).unwrap();
    let row: (Vec<u8>, Vec<u8>) = conn.query_row("SELECT checkpoint_finality,p_digest FROM native_later_epoch_pre_handoff_v1 WHERE checkpoint_block=?1", [checkpoint.id().as_bytes()], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    assert_eq!(row.0, original_proof);
    assert_eq!(row.1, original_p);
    let attached: i64 = conn
        .query_row("SELECT COUNT(*) FROM native_later_epoch_edge_v1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        attached, 0,
        "no new successor may exist before both role quorums"
    );
    let schema: Vec<u8> = conn
        .query_row(
            "SELECT schema_version FROM native_application_metadata_v0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(schema, 13u64.to_be_bytes());
    Box::new((directory, owner, key))
}

#[inline(never)]
fn pre_handoff_cold_v5(case: Box<PreHandoffCaseV5>) {
    let (_directory, owner, mut key) = *case;
    let inner = owner.inner.as_ref().unwrap();
    let path = inner.runtime.application.path().to_path_buf();
    let receipt = owner.receipt.as_ref().unwrap();
    let block = *receipt.header().id().as_bytes();
    let expected_cut = receipt.committed_owner_cut_ref_v1();
    let calls = key.calls;
    assert!(owner.sign_seal_vote_v5(&mut key).is_err());
    assert_eq!(key.calls, calls);
    let app =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    let recovered = app.recover_later_epoch_pre_handoff_v1(block).unwrap();
    assert_eq!(recovered.committed_owner_cut_ref_v1(), expected_cut);
    assert_eq!(recovered.head().height().get(), 18);
}

#[test]
fn actual_epoch_seals_apply_original_fronts_then_commit_unattached_pre_handoff_v5() {
    let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
    let unsigned = first_apply_unsigned_v2(live);
    let first = first_apply_children_v2(first_apply_start_v2(unsigned));
    let cutoff = ordinary_cutoff_advance_v3(ordinary_cutoff_begin_v3(first));
    let checkpoint = checkpoint_prepare_execute_v4(checkpoint_prepare_begin_v4(cutoff));
    let first_seal = pre_handoff_seal_and_apply_v5(pre_handoff_begin_v5(checkpoint));
    let second_seal = pre_handoff_seal_and_apply_v5(first_seal);
    pre_handoff_cold_v5(pre_handoff_commit_v5(second_seal));
}

#[inline(never)]
fn seal_native_replacement_rejects_v5(case: Box<PreHandoffCaseV5>, watermark: Watermark) {
    let (_directory, owner, mut key) = *pre_handoff_pending_seal_vote_v5(case);
    let inner = owner.inner.as_ref().unwrap();
    assert_eq!(inner.runtime.checkpoint.fields().application.height, 16);
    let path = inner.runtime.application.path().to_path_buf();
    let checkpoint_id = inner
        .prepared
        .last()
        .unwrap()
        .prepared
        .header()
        .unwrap()
        .id();
    let expected_bytes = std::fs::read(&path).unwrap();
    let sequence = watermark.0.lock().unwrap().0.unwrap().sequence();
    *watermark.3.lock().unwrap() = Some((path.clone(), sequence + 1));
    let calls = key.calls;
    let error = owner
        .sign_seal_vote_v5(&mut key)
        .err()
        .expect("namespace substitution must reject");
    assert!(
        watermark.3.lock().unwrap().is_none(),
        "actual external callback must run; earlier error: {error:#}"
    );
    assert_eq!(
        key.calls, calls,
        "seal owner substitution must reject before key entry"
    );
    assert_eq!(std::fs::read(&path).unwrap(), expected_bytes);
    let application =
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
    assert_eq!(
        application
            .confirmed_committed_head_v0()
            .unwrap()
            .height()
            .get(),
        16
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM native_durable_execution_p_v1 WHERE block_id=?1 AND status=0",
            [checkpoint_id.as_bytes()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 1,
        "replacement retains the original genuine checkpoint P"
    );
}

#[test]
fn actual_epoch_seal_native_replacement_rejects_before_key_v5() {
    let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
    let unsigned = first_apply_unsigned_v2(live);
    let watermark = unsigned.3.new_watermark.clone();
    let first = first_apply_children_v2(first_apply_start_v2(unsigned));
    let cutoff = ordinary_cutoff_advance_v3(ordinary_cutoff_begin_v3(first));
    let checkpoint = checkpoint_prepare_execute_v4(checkpoint_prepare_begin_v4(cutoff));
    seal_native_replacement_rejects_v5(pre_handoff_begin_v5(checkpoint), watermark);
}
