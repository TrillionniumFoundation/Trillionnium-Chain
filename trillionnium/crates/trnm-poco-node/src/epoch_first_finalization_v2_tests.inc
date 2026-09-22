// Every peer signature below is genuine public evidence. The local Vote still
// passes through the actual runtime's Safety and signer-journal barriers.
fn first_apply_qc_v2(
    header: &BlockHeader,
    set: &trnm_consensus_types::ValidatorSet,
) -> trnm_consensus_types::QuorumCertificate {
    use trnm_consensus_types::{QuorumCertificate, Vote};
    let root =
        Vote::signing_root_for_set(set, header.view(), header.height(), header.id()).unwrap();
    let votes = set
        .validators()
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            let key = SigningKey::from_bytes(&[20 + index as u8; 32]);
            assert_eq!(
                key.verifying_key().to_bytes(),
                validator.consensus_key().into_bytes()
            );
            Vote::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                header.view(),
                header.height(),
                header.id(),
                set.id(),
                validator.id(),
                SignatureBytes::from_array(key.sign(root.as_bytes()).to_bytes()),
                set,
            )
            .unwrap()
        })
        .collect();
    QuorumCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        header.view(),
        header.height(),
        header.id(),
        set.id(),
        votes,
        set,
    )
    .unwrap()
}

#[inline(never)]
fn first_apply_child_proposal_v2(
    owner: &super::FirstEpochFinalizationRuntimeV2<Watermark, Watermark>,
) -> SignedProposalV0 {
    application_child_proposal_v4(owner, None)
}

#[inline(never)]
fn application_child_proposal_v4(
    owner: &super::FirstEpochFinalizationRuntimeV2<Watermark, Watermark>,
    commitment: Option<trnm_consensus_types::NextEpochCommitmentHash>,
) -> SignedProposalV0 {
    let parent = &owner.prepared.last().unwrap().prepared;
    let parent_header = parent.header().unwrap();
    let set = owner.runtime.edge.new_validator_set();
    let parameters = owner.runtime.edge.new_parameters();
    let request = trnm_native_execution_v0::NativeBlockPreviewRequestV0::new(
        trnm_native_application::ChainIdV0::new(set.chain_id().as_str()).unwrap(),
        trnm_native_application::GenesisHashV0::new(*set.genesis_hash().as_bytes()).unwrap(),
        parent.overlay_parent_head().unwrap(),
        trnm_native_application::HeightV0::new(parent_header.height().get() + 1),
        parent_header.timestamp_ms() + 1,
        trnm_native_application::ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),
        Vec::new(),
    )
    .unwrap();
    let preview = owner
        .runtime
        .application
        .preview_epoch_descendant_v1(parent, &request)
        .unwrap();
    let view = View::new(parent_header.view().get() + 1);
    let proposer = trnm_consensus_core::leader_for(set, view);
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        view,
        trnm_consensus_types::Height::new(request.height().get()),
        if commitment.is_some() {
            BlockKind::EpochCheckpoint
        } else {
            BlockKind::Regular
        },
        parent_header.id(),
        proposer,
        set.id(),
        parameters.hash(),
        PayloadDigest::new(*preview.payload_root().as_bytes()),
        StateRoot::new(*preview.post_state_root().as_bytes()),
        ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
        EvidenceRoot::new(*preview.evidence_root().as_bytes()),
        request.timestamp_ms(),
        commitment,
    )
    .unwrap();
    let justify = QcReferenceV0::ordinary(first_apply_qc_v2(&parent_header, set));
    let root = ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
    let index = set
        .validators()
        .iter()
        .position(|validator| validator.id() == proposer)
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
        parent_header.timestamp_ms(),
    )
    .unwrap();
    SignedProposalV0::new(
        Block::new(
            header,
            trnm_consensus_types::ApplicationPayloadV0::new(Vec::new())
                .unwrap()
                .try_cev0_bytes()
                .unwrap(),
            Vec::new(),
        )
        .unwrap(),
        witness,
        set,
        None,
        parameters,
        parent_header.timestamp_ms(),
    )
    .unwrap()
}

type FirstApplyCaseV2 = (
    tempfile::TempDir,
    super::FirstEpochFinalizationRuntimeV2<Watermark, Watermark>,
    Key,
);

#[inline(never)]
fn first_apply_unsigned_v2(live: Box<LiveCaseV1>) -> Box<LiveCaseV1> {
    let (directory, runtime, key, recovery) = *live;
    let proposal = native_first_proposal_v1(
        &runtime.application,
        &runtime.edge,
        recovery.proposal.witness().justify_qc(),
        recovery
            .proposal
            .witness()
            .epoch_anchor_authorization()
            .unwrap(),
    );
    let runtime = runtime.admit_epoch_proposal_v1(proposal).unwrap();
    let (runtime, _) = runtime.execute_admitted_epoch_proposal_v1().unwrap();
    Box::new((directory, runtime, key, recovery))
}

#[inline(never)]
fn first_apply_start_v2(live: Box<LiveCaseV1>) -> Box<FirstApplyCaseV2> {
    let (directory, runtime, mut key, _recovery) = *live;
    let (runtime, _) = runtime.sign_pending_epoch_vote_v1(&mut key).unwrap();
    let owner = runtime.begin_first_finalization_v2().unwrap();
    assert!(
        owner
            .runtime
            .driver
            .issue_application_finalization_permit_v1()
            .is_err(),
        "a signed first block alone cannot create Core finality"
    );
    Box::new((directory, owner, key))
}

#[inline(never)]
fn first_apply_children_v2(case: Box<FirstApplyCaseV2>) -> Box<FirstApplyCaseV2> {
    let (directory, mut owner, mut key) = *case;
    for expected_count in 2..=3 {
        let proposal = first_apply_child_proposal_v2(&owner);
        let block = proposal.block().id();
        let calls = key.calls;
        owner = owner.execute_child_proposal_v2(proposal).unwrap();
        assert_eq!(key.calls, calls, "real child P/D/C cannot invoke the key");
        assert!(owner.runtime.driver.state().pending_sign().is_some());
        let (next, vote) = owner.sign_child_vote_v2(&mut key).unwrap();
        owner = next;
        assert_eq!(key.calls, calls + 1);
        let trnm_consensus_core::OutboundMessage::Vote(vote) = vote else {
            panic!("child must sign Vote")
        };
        assert_eq!(vote.block_id(), block);
        assert_eq!(owner.prepared.len(), expected_count);
        let p = &owner.prepared.last().unwrap().prepared;
        let read = owner
            .runtime
            .application
            .confirm_prepared_epoch_execution_v1(p)
            .unwrap();
        assert_eq!(read.commit_sequence(), None);
        assert_eq!(read.prepared().header().unwrap().id(), block);
    }
    Box::new((directory, owner, key))
}

#[inline(never)]
fn first_apply_settle_v2(case: Box<FirstApplyCaseV2>) -> Box<FirstApplyCaseV2> {
    let (directory, owner, key) = *case;
    let first = owner.prepared[0].prepared.header().unwrap();
    let third = owner.prepared[2].prepared.header().unwrap();
    let child_pins: Vec<_> = owner.prepared[1..]
        .iter()
        .map(|p| (p.prepared.header().unwrap().id(), p.prepared.p_digest()))
        .collect();
    let calls = key.calls;
    let qc = first_apply_qc_v2(&third, owner.runtime.edge.new_validator_set());
    let owner = owner.observe_first_finality_qc_v2(qc).unwrap();
    assert_eq!(
        owner.runtime.driver.state().finalized().block_id(),
        first.id()
    );
    assert_ne!(
        owner
            .runtime
            .driver
            .state()
            .application_applied()
            .block_id(),
        first.id()
    );
    assert!(owner
        .runtime
        .driver
        .state()
        .pending_finalization()
        .is_some());
    let mut owner = owner
        .apply_first_finalization_v2(
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
    let checkpoint = owner.settled_checkpoint_v2().unwrap();
    assert_eq!(
        key.calls, calls,
        "Core/native finality cannot invoke the signer"
    );
    assert_eq!(
        checkpoint.fields().application.block_id,
        *first.id().as_bytes()
    );
    assert_eq!(
        owner
            .runtime
            .driver
            .state()
            .application_applied()
            .block_id(),
        first.id()
    );
    assert!(owner.runtime.driver.state().finalization_queue().is_empty());
    let read = owner
        .runtime
        .journal
        .fresh_read_v1(owner.runtime.pin)
        .unwrap();
    assert_eq!(read.state_v1(), owner.runtime.driver.state());
    assert!(read
        .transition_context_v1()
        .native_finalization_applied_transition()
        .is_some());
    for (block, digest) in child_pins {
        let p = owner
            .runtime
            .application
            .reopen_prepared_epoch_execution_v1(*block.as_bytes())
            .unwrap();
        assert_eq!(p.p_digest(), digest);
        assert_eq!(
            owner
                .runtime
                .application
                .confirm_prepared_epoch_execution_v1(&p)
                .unwrap()
                .commit_sequence(),
            None
        );
    }
    Box::new((directory, owner, key))
}

#[inline(never)]
fn first_apply_finish_v2(case: Box<FirstApplyCaseV2>) {
    let (_directory, owner, _key) = *first_apply_settle_v2(case);
    assert!(
        owner
            .apply_first_finalization_v2(
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0()
            )
            .is_err(),
        "completed application permit cannot be consumed twice"
    );
}

#[test]
fn actual_epoch_first_core_finalization_applies_three_real_native_executions_v2() {
    let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
    let unsigned = first_apply_unsigned_v2(live);
    first_apply_finish_v2(first_apply_children_v2(first_apply_start_v2(unsigned)));
}

#[inline(never)]
fn assert_vote_p_deleted_before_key_v2(live: Box<LiveCaseV1>) {
    let (_directory, runtime, mut key, recovery) = *live;
    let pending = runtime.pending_epoch_commit.as_ref().unwrap();
    let block = *pending.prepared.header().unwrap().id().as_bytes();
    let path = runtime.application.path().to_path_buf();
    let parent = runtime.application.confirmed_committed_head_v0().unwrap();
    let calls = key.calls;
    *recovery.new_watermark.2.lock().unwrap() = Some((path.clone(), block));
    assert!(runtime.sign_pending_epoch_vote_v1(&mut key).is_err());
    assert!(
        recovery.new_watermark.2.lock().unwrap().is_none(),
        "external callback actually removed P"
    );
    assert_eq!(
        key.calls, calls,
        "a missing durable P must reject before entering the key"
    );
    // Removal also violates the retained P inventory. The committed metadata
    // itself stays unchanged; cold recovery must reject the damaged inventory.
    let connection = rusqlite::Connection::open(&path).unwrap();
    let metadata: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT head_height, head_block_id, head_state_root, head_commit_id
             FROM native_application_metadata_v0",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(metadata.0, parent.height().get().to_be_bytes());
    assert_eq!(metadata.1, parent.block_id().as_bytes());
    assert_eq!(metadata.2, parent.state_root().as_bytes());
    assert_eq!(metadata.3, parent.commit_id().as_bytes());
    drop(connection);
    assert!(
        DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).is_err()
    );
}

#[test]
fn actual_epoch_vote_rejects_deleted_native_p_at_external_key_boundary_v2() {
    let live = activate_actual_case_v1(build_epoch_runtime_case_v1());
    let unsigned = first_apply_unsigned_v2(live);
    assert_vote_p_deleted_before_key_v2(unsigned);
}

include!("epoch_ordinary_continuation_v3_tests.inc");

include!("epoch_checkpoint_preparation_v4_tests.inc");
