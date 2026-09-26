#[test]
fn contextual_certified_header_roundtrips_real_handoff_regular_checkpoint_and_seals() {
    let runtime = StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let first = first_epoch_finality_for_context(&runtime);
    let (evidence, set, parameters, _, _) =
        successor_evidence_variant(&runtime, true, SuccessorBadSignature::None);
    let decoded = decode_epoch_activation_evidence_with_context_v1_exact(
        evidence.as_preimages(),
        runtime.structural_context(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let later = decoded.old_checkpoint_finality();
    for (certified, parent) in [
        (
            first.finalized_block(),
            runtime.activation().terminal_old_header(),
        ),
        (first.child(), first.finalized_block().header()),
        (first.grandchild(), first.child().header()),
        (
            later.finalized_block(),
            decoded.authenticated_checkpoint_parent_header(),
        ),
        (later.child(), later.finalized_block().header()),
        (later.grandchild(), later.child().header()),
    ] {
        let bytes = certified.try_cev0_bytes().unwrap();
        let mut structural_budget = Cev0AdmissionBudgetV0::protocol_v0();
        let structural = decode_epoch_runtime_certified_header_v1_exact_with_budget(
            &bytes,
            runtime.structural_context(),
            parent.timestamp_ms(),
            &mut structural_budget,
        )
        .unwrap();
        assert_eq!(structural, *certified);
        let work = structural_budget.signature_work();
        assert!(work > 0);
        let mut exact = Cev0AdmissionBudgetV0::new(bytes.len(), work + 7);
        exact.charge_signature_work(7).unwrap();
        assert_eq!(
            runtime
                .decode_verify_certified_header_v1(&bytes, parent, &mut exact)
                .unwrap(),
            *certified
        );
        assert_eq!(exact.signature_work(), work + 7);
        let mut typed = Cev0AdmissionBudgetV0::new(bytes.len(), work + 7);
        typed.charge_signature_work(7).unwrap();
        runtime
            .verify_certified_header_v1(certified, parent, &mut typed)
            .unwrap();
        assert_eq!(typed.signature_work(), exact.signature_work());
        let mut short = Cev0AdmissionBudgetV0::new(bytes.len(), work + 6);
        short.charge_signature_work(7).unwrap();
        assert!(runtime
            .decode_verify_certified_header_v1(&bytes, parent, &mut short)
            .is_err());
        assert_eq!(short.signature_work(), 7);
        let mut short_bytes = Cev0AdmissionBudgetV0::new(bytes.len() - 1, work + 7);
        short_bytes.charge_signature_work(7).unwrap();
        assert!(runtime
            .decode_verify_certified_header_v1(&bytes, parent, &mut short_bytes)
            .is_err());
        assert_eq!(short_bytes.signature_work(), 7);
        let mut trailing = bytes.clone();
        trailing.push(0);
        let mut trailing_budget = Cev0AdmissionBudgetV0::protocol_v0();
        trailing_budget.charge_signature_work(7).unwrap();
        assert!(runtime
            .decode_verify_certified_header_v1(&trailing, parent, &mut trailing_budget)
            .is_err());
        assert_eq!(trailing_budget.signature_work(), 7);
    }
    // Mixed TC contains both a real ordinary QC and the exact contextual
    // anchor. A context-free decoder must retain its previous restriction.
    assert!(decode_ordinary_certified_header_v0_exact_with_budget(
        &later.finalized_block().try_cev0_bytes().unwrap(),
        &set,
        &parameters,
        decoded
            .authenticated_checkpoint_parent_header()
            .timestamp_ms(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .is_err());
}

#[test]
fn contextual_certified_header_rejects_each_real_signature_family_without_refund() {
    let runtime = StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    for bad in [
        SuccessorBadSignature::ParentQc,
        SuccessorBadSignature::CheckpointQc,
        SuccessorBadSignature::CheckpointProposal,
        SuccessorBadSignature::CheckpointTimeout,
    ] {
        let (evidence, _, _, _, _) = successor_evidence_variant(&runtime, true, bad);
        let decoded = decode_epoch_activation_evidence_with_context_v1_exact(
            evidence.as_preimages(),
            runtime.structural_context(),
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
        let parent = decoded.authenticated_checkpoint_parent_header();
        let certified = decoded.old_checkpoint_finality().finalized_block();
        let bytes = certified.try_cev0_bytes().unwrap();
        let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
        decode_epoch_runtime_certified_header_v1_exact_with_budget(
            &bytes,
            runtime.structural_context(),
            parent.timestamp_ms(),
            &mut measured,
        )
        .unwrap();
        let mut actual = Cev0AdmissionBudgetV0::protocol_v0();
        actual.charge_signature_work(7).unwrap();
        assert!(
            runtime
                .decode_verify_certified_header_v1(&bytes, parent, &mut actual)
                .is_err(),
            "{bad:?}"
        );
        assert_eq!(
            actual.signature_work(),
            measured.signature_work() + 7,
            "{bad:?}"
        );
        let mut typed = Cev0AdmissionBudgetV0::protocol_v0();
        typed.charge_signature_work(7).unwrap();
        assert!(
            runtime
                .verify_certified_header_v1(certified, parent, &mut typed)
                .is_err(),
            "{bad:?}"
        );
        assert_eq!(typed.signature_work(), actual.signature_work());
    }
}

#[test]
fn contextual_certified_header_requires_exact_parent_and_complete_epoch_context() {
    let runtime = StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, _, _, _, ancestry) =
        successor_evidence_variant(&runtime, true, SuccessorBadSignature::None);
    let decoded = decode_epoch_activation_evidence_with_context_v1_exact(
        evidence.as_preimages(),
        runtime.structural_context(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let parent = decoded.authenticated_checkpoint_parent_header();
    let certified = decoded.old_checkpoint_finality().finalized_block();
    let bytes = certified.try_cev0_bytes().unwrap();
    // A real but different parent has valid shape and context; exact ID/height
    // joining must still reject it before any caller can reserve native work.
    assert!(runtime
        .decode_verify_certified_header_v1(
            &bytes,
            &ancestry[ancestry.len() - 2],
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err());
    let successor = decode_verify_successor_epoch_activation_strict_v1(
        runtime.activation(),
        &ancestry,
        evidence.as_preimages(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let foreign = StrictEpochRuntimeContextV1::from_activation_v1(successor).unwrap();
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    budget.charge_signature_work(7).unwrap();
    assert!(foreign
        .decode_verify_certified_header_v1(&bytes, parent, &mut budget)
        .is_err());
    assert_eq!(budget.signature_work(), 7);
    // A Handoff's old parent must be the precise terminal header sealed by the
    // same runtime, not merely an old-epoch header with an acceptable timestamp.
    let first = first_epoch_finality_for_context(&runtime);
    assert!(runtime
        .decode_verify_certified_header_v1(
            &first.finalized_block().try_cev0_bytes().unwrap(),
            parent,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err());
}

#[test]
fn contextual_certified_header_typed_handoff_rejects_unverified_authorization_substitution() {
    let runtime = StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let activation = runtime.activation();
    let mut forged_evidence = runtime.evidence_bytes().clone();
    // Keep all descriptor/anchor coordinates, but corrupt a B-role signature.
    // The eight-root structural decoder intentionally grants no crypto claim.
    *forged_evidence.authorization_kernel.last_mut().unwrap() ^= 1;
    let decoded = decode_epoch_activation_evidence_v0_exact(
        forged_evidence.as_preimages(),
        activation.old_validator_set(),
        activation.old_consensus_parameters(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let unverified = EpochRuntimeContextDataV1::from_decoded_evidence_v1(&decoded).unwrap();
    assert_eq!(unverified.anchor_reference(), runtime.anchor_reference());
    assert_ne!(
        unverified.authorization(),
        runtime.structural_context().authorization()
    );
    let first = first_epoch_finality_for_context(&runtime);
    let original = first.finalized_block();
    let set = activation.new_validator_set();
    let parent = activation.terminal_old_header();
    // Re-sign the real proposal around the substituted authorization. Thus
    // checking only QC coordinates plus proposer/QC signatures would pass.
    let root = ProposalWitnessV0::signing_root_for(
        original.header(),
        unverified.anchor_reference(),
        None,
        Some(unverified.authorization()),
    )
    .unwrap();
    let signature = Signature64::from_array(
        signing_key(set.validator(original.header().proposer_id()).unwrap())
            .sign(root.as_bytes())
            .to_bytes(),
    );
    let substituted = CertifiedHeaderV0::new(
        original.header().clone(),
        unverified.anchor_reference().clone(),
        None,
        Some(unverified.authorization().clone()),
        signature,
        original.certifying_qc().clone(),
        set,
        Some(activation.old_validator_set()),
        activation.new_consensus_parameters(),
        parent.timestamp_ms(),
    )
    .unwrap();
    let substituted_finality = FinalityProofV0::new(
        substituted.clone(),
        first.child().clone(),
        first.grandchild().clone(),
        set,
        Some(activation.old_validator_set()),
        activation.new_consensus_parameters(),
        parent.timestamp_ms(),
    )
    .unwrap();
    assert!(
        runtime
            .verify_finality_v1(
                &substituted_finality,
                parent.timestamp_ms(),
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .is_err(),
        "existing typed finality must bind the same complete authorization"
    );
    assert!(
        runtime
            .verify_certified_header_v1(
                &substituted,
                parent,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .is_err(),
        "typed admission must bind the complete verified authorization"
    );
    assert!(runtime
        .decode_verify_certified_header_v1(
            &substituted.try_cev0_bytes().unwrap(),
            parent,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err());
}
