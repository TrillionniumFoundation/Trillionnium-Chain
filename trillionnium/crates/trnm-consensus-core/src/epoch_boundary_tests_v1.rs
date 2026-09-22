use super::*;

fn boundary_proposal_v1(
    set: &ValidatorSet,
    parameters: &ConsensusParametersV0,
    justify: QuorumCertificate,
    kind: BlockKind,
    state_root: StateRoot,
) -> SignedProposalV0 {
    let payload = ApplicationPayloadV0::new(Vec::new()).unwrap();
    let receipts = ExecutionReceiptsV0::new(&payload, Vec::new()).unwrap();
    let body = BlockBodyV0::new(payload, Vec::new()).unwrap();
    let height = justify.height().checked_next().unwrap();
    let view = justify.view().checked_next().unwrap();
    let header = BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        view,
        height,
        kind,
        justify.block_id(),
        leader_for(set, view),
        set.id(),
        parameters.hash(),
        body.payload_root().unwrap(),
        state_root,
        receipts.receipts_root().unwrap(),
        body.evidence_root().unwrap(),
        height.get() * 100,
        Some(NextEpochCommitmentHash::new([0x37; 32])),
    )
    .unwrap();
    let block = Block::new(
        header,
        body.application_payload().try_cev0_bytes().unwrap(),
        Vec::new(),
    )
    .unwrap();
    signed_proposal_from_block(
        set,
        parameters,
        block,
        QcReferenceV0::ordinary(justify),
        None,
        (height.get() - 1) * 100,
    )
    .unwrap()
}

fn finish_boundary_signature_v1(core: &mut Core, effects: Vec<Effect>) {
    assert_boundary_record_roundtrip_v1(core.config(), persistence_request(&effects).state());
    let released = release_persisted_effects(core, effects);
    let (id, root) = signature_request(&released);
    assert!(matches!(
        core.step(
            Input::SignatureReady {
                id,
                signature: signature(root)
            },
            &RootSignatures
        )
        .unwrap()
        .as_slice(),
        [Effect::Broadcast(OutboundMessage::Vote(_))]
    ));
}

#[test]
fn old_epoch_boundary_v1_drives_checkpoint_and_two_seals_without_seal_execution() {
    let (config, mut core, set, parameters, q2) = short_epoch_core_before_last_regular();
    let old = core.safety_state().clone();
    let migration = core.prepare_old_epoch_boundary_v1(1).unwrap();
    assert_eq!(persistence_request(&migration).state().schema_version(), 14);
    assert_boundary_record_roundtrip_v1(&config, persistence_request(&migration).state());
    assert!(release_persisted_effects(&mut core, migration).is_empty());
    assert_eq!(core.safety_state().finalized(), old.finalized());
    let apply = finalization_apply_authority_for_test(&core);
    let third = proposal_with_parameters(&set, &parameters, q2, 3, b"old final regular");
    let q3 = qc(&set, 3, 3, third.block().id());
    insert_valid_and_vote(&mut core, third);
    accept_qc(&mut core, q3.clone());
    let applied = apply_finalization_for_test(&mut core, &apply).unwrap();
    release_persisted_effects(&mut core, applied);
    let checkpoint = boundary_proposal_v1(
        &set,
        &parameters,
        q3,
        BlockKind::EpochCheckpoint,
        StateRoot::new([0x34; 32]),
    );
    let pending = core
        .step(
            Input::Proposal(Box::new(checkpoint.clone())),
            &RootSignatures,
        )
        .unwrap();
    let request = release_persisted_effects(&mut core, pending);
    let id = validation_effect(&request);
    let payload = ApplicationPayloadV0::new(Vec::new()).unwrap();
    let receipts = ExecutionReceiptsV0::new(&payload, Vec::new()).unwrap();
    let body = BlockBodyV0::new(payload, Vec::new()).unwrap();
    let h = checkpoint.block().header();
    let commitments = body
        .validate_checkpoint_static_commitments(
            h,
            &receipts,
            &parameters,
            h.state_root(),
            h.next_epoch_commitment_hash().unwrap(),
        )
        .unwrap();
    let result = PayloadValidationResult::authorized_valid_v0(
        commitments.application_commitments_v1(),
        artifact_ref_for_ids(h.id(), h.parent_id()),
    );
    let voted = core
        .step(Input::PayloadValidated { id, result }, &RootSignatures)
        .unwrap();
    finish_boundary_signature_v1(&mut core, voted);
    let q4 = qc(&set, 4, 4, h.id());
    let finalized = accept_qc(&mut core, q4.clone());
    assert!(finalized.iter().any(|e| matches!(e, Effect::Finalize(_))));
    let applied = apply_finalization_for_test(&mut core, &apply).unwrap();
    release_persisted_effects(&mut core, applied);
    let before_seals = core.safety_state().payload_validation_completions().len();
    let seal1 = boundary_proposal_v1(&set, &parameters, q4, BlockKind::EpochSeal1, h.state_root());
    let malformed = boundary_proposal_v1(
        &set,
        &parameters,
        seal1.witness().justify_qc().as_ordinary().unwrap().clone(),
        BlockKind::EpochSeal1,
        StateRoot::new([0x99; 32]),
    );
    // A sync consumer retains the same authenticated seal without scheduling
    // an application artifact or issuing a vote. Replaying it is idempotent.
    let mut follower = core.clone();
    let old_view = follower.safety_state().current_view();
    let old_vote = follower.safety_state().last_voted_view();
    let replay = follower
        .step(
            Input::SyncedProposal(Box::new(seal1.clone())),
            &RootSignatures,
        )
        .unwrap();
    assert_boundary_record_roundtrip_v1(&config, persistence_request(&replay).state());
    assert!(release_persisted_effects(&mut follower, replay).is_empty());
    assert_eq!(follower.safety_state().current_view(), old_view);
    assert_eq!(follower.safety_state().last_voted_view(), old_vote);
    assert!(follower.safety_state().pending_sign().is_none());
    assert!(follower
        .safety_state()
        .payload_terminal_fact(seal1.block().id())
        .is_none());
    assert!(follower
        .safety_state()
        .payload_validation_obligations()
        .is_empty());
    assert!(follower
        .step(
            Input::SyncedProposal(Box::new(seal1.clone())),
            &RootSignatures
        )
        .unwrap()
        .is_empty());
    let before = core.clone();
    assert!(core
        .step(Input::Proposal(Box::new(malformed)), &RootSignatures)
        .is_err());
    assert_eq!(core, before);
    let wrong_body = Block::new(
        seal1.block().header().clone(),
        ApplicationPayloadV0::new(vec![b"not empty".to_vec()])
            .unwrap()
            .try_cev0_bytes()
            .unwrap(),
        Vec::new(),
    )
    .unwrap();
    let wrong_body = SignedProposalV0::new(
        wrong_body,
        seal1.witness().clone(),
        &set,
        None,
        &parameters,
        h.timestamp_ms(),
    )
    .unwrap();
    assert!(core
        .step(Input::Proposal(Box::new(wrong_body)), &RootSignatures)
        .is_err());
    assert_eq!(core, before);
    let effects = core
        .step(Input::Proposal(Box::new(seal1.clone())), &RootSignatures)
        .unwrap();
    finish_boundary_signature_v1(&mut core, effects);
    assert_eq!(
        core.safety_state().payload_validation_completions().len(),
        before_seals
    );
    assert!(core
        .safety_state()
        .payload_terminal_fact(seal1.block().id())
        .is_none());
    let q5 = qc(&set, 5, 5, seal1.block().id());
    accept_qc(&mut core, q5.clone());
    let applied = apply_finalization_for_test(&mut core, &apply).unwrap();
    release_persisted_effects(&mut core, applied);
    let seal2 = boundary_proposal_v1(&set, &parameters, q5, BlockKind::EpochSeal2, h.state_root());
    let effects = core
        .step(Input::Proposal(Box::new(seal2.clone())), &RootSignatures)
        .unwrap();
    finish_boundary_signature_v1(&mut core, effects);
    assert!(core
        .safety_state()
        .payload_terminal_fact(seal2.block().id())
        .is_none());
    let finalized = accept_qc(&mut core, qc(&set, 6, 6, seal2.block().id()));
    assert!(finalized.iter().any(|e| matches!(e, Effect::Finalize(_))));
    assert_eq!(core.safety_state().finalized().block_id(), h.id());
    assert_eq!(
        core.safety_state().application_applied().height(),
        Height::new(3)
    );
    let applied = apply_finalization_for_test(&mut core, &apply).unwrap();
    release_persisted_effects(&mut core, applied);
    assert_eq!(
        core.safety_state().application_applied().height(),
        Height::new(4)
    );
    assert_eq!(
        core.safety_state()
            .old_epoch_boundary_v1()
            .unwrap()
            .phase(core.safety_state()),
        OldEpochBoundaryPhaseV1::CheckpointApplied
    );
    Core::validate_persisted_state_v0(&config, core.safety_state(), &RootSignatures).unwrap();
    assert_boundary_record_roundtrip_v1(&config, core.safety_state());
    assert!(Core::recover(config, core.safety_state().clone(), &RootSignatures).is_err());
}

fn assert_boundary_record_roundtrip_v1(config: &CoreConfig, state: &SafetyState) {
    let limits = minimum_old_epoch_boundary_record_limits_v1(config).unwrap();
    let context = SafetyStateRecordContextV0::new(config, [0x73; 32], limits).unwrap();
    let raw = encode_old_epoch_boundary_safety_record_v1(state, &context).unwrap();
    assert!(encode_safety_state_record_v0(state, &context).is_err());
    assert!(decode_safety_state_record_v0_exact(&raw, &context).is_err());
    let decoded = decode_old_epoch_boundary_safety_record_v1_exact(&raw, &context).unwrap();
    assert_eq!(decoded.state(), state);
    Core::validate_persisted_state_v0(config, decoded.state(), &RootSignatures).unwrap();
    let mut changed = raw.clone();
    changed[61] ^= 1;
    assert_eq!(
        decode_old_epoch_boundary_safety_record_v1_exact(&changed, &context),
        Err(SafetyStateRecordErrorV0::ConfigMismatch)
    );
    let mut changed = raw.clone();
    changed.push(0);
    assert!(decode_old_epoch_boundary_safety_record_v1_exact(&changed, &context).is_err());
    let mut changed = raw;
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(
        decode_old_epoch_boundary_safety_record_v1_exact(&changed, &context),
        Err(SafetyStateRecordErrorV0::ChecksumMismatch)
    );
}

#[test]
fn strict_old_epoch_boundary_owner_rejects_unit_signature_state() {
    let (_, core, _, _, _) = short_epoch_core_before_last_regular();
    assert!(core.into_old_epoch_boundary_v1(1).is_err());
}

#[test]
fn old_epoch_boundary_migration_changes_only_owner_schema_and_revision() {
    let (config, mut core, _, _, _) = short_epoch_core_before_last_regular();
    let old = core.safety_state().clone();
    let effects = core.prepare_old_epoch_boundary_v1(9).unwrap();
    let next = persistence_request(&effects).state();
    Core::validate_persisted_successor_v0(&config, &old, next, &RootSignatures).unwrap();
    let mut extra_change = next.clone();
    extra_change.set_current_view(next.current_view().checked_next().unwrap());
    assert!(
        Core::validate_persisted_successor_v0(&config, &old, &extra_change, &RootSignatures)
            .is_err()
    );
}
