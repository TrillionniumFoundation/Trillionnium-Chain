// Real successor evidence: the TC anchor is derived from the fully verified
// predecessor. No hand-built synthetic reference or permissive verifier exists.
use trnm_consensus_crypto::{
    decode_verify_successor_epoch_activation_strict_v1,
    recover_successor_epoch_activation_authority_strict_v1,
};

#[test]
fn contextual_successor_accepts_signed_mixed_anchor_timeouts_and_recovers_exact_bytes() {
    let predecessor = StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, old_set, old_parameters, binding, ancestry) =
        successor_evidence_variant(&predecessor, true, SuccessorBadSignature::None);
    for pair in ancestry.windows(2) {
        validate_historical_header_link_v1(&pair[1], &pair[0], &old_set, &old_parameters).unwrap();
    }
    let mut old_budget = Cev0AdmissionBudgetV0::protocol_v0();
    assert!(
        decode_epoch_activation_evidence_v0_exact(
            evidence.as_preimages(),
            &old_set,
            &old_parameters,
            &mut old_budget,
        )
        .is_err(),
        "the context-free decoder must not authorize a synthetic TC reference"
    );
    assert_eq!(old_budget.signature_work(), 0);
    assert!(recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .is_err());

    let mut structural_budget = Cev0AdmissionBudgetV0::protocol_v0();
    let decoded = decode_epoch_activation_evidence_with_context_v1_exact(
        evidence.as_preimages(),
        predecessor.structural_context(),
        &mut structural_budget,
    )
    .unwrap();
    derive_successor_epoch_joint_structure_v1(&decoded, predecessor.structural_context()).unwrap();
    let proof = decoded.old_checkpoint_finality();
    let parent = decoded.authenticated_checkpoint_parent_header();
    for (certified, parent) in [
        (proof.finalized_block(), parent),
        (proof.child(), proof.finalized_block().header()),
        (proof.grandchild(), proof.child().header()),
    ] {
        let timeout = certified.timeout_certificate().unwrap();
        assert_eq!(certified.header().view().get(), parent.view().get() + 2);
        assert_eq!(timeout.timed_out_view().get(), parent.view().get() + 1);
        assert_eq!(timeout.referenced_qcs().len(), 2);
        assert!(timeout
            .referenced_qcs()
            .contains(predecessor.anchor_reference()));
        assert_eq!(predecessor.anchor_reference().qc_ref().view(), View::new(0));
        assert_eq!(
            predecessor.anchor_reference().qc_ref().block_id(),
            predecessor.activation().terminal_old_header().id()
        );
        assert_eq!(
            timeout.selected_high_qc_digest(),
            certified.justify_qc().id()
        );
        assert_eq!(certified.justify_qc().qc_ref().block_id(), parent.id());
    }
    // The same proof independently verifies through the outgoing live runtime.
    assert_eq!(
        predecessor
            .decode_verify_finality_v1(
                &evidence.old_checkpoint_finality,
                parent.timestamp_ms(),
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap(),
        *proof
    );

    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let successor = decode_verify_successor_epoch_activation_strict_v1(
        predecessor.activation(),
        &ancestry,
        evidence.as_preimages(),
        &mut budget,
    )
    .unwrap();
    assert_eq!(budget.signature_work(), structural_budget.signature_work());
    assert_eq!(*successor.binding_ref().as_bytes(), binding);
    let successor_runtime = StrictEpochRuntimeContextV1::from_activation_v1(successor).unwrap();
    assert_eq!(successor_runtime.evidence_bytes(), &evidence);
    let successor_runtime = StrictEpochRuntimeContextV1::compose_successor_v1(
        &predecessor,
        successor_runtime,
        &ancestry,
    )
    .unwrap();
    assert_eq!(
        successor_runtime.activation().new_validator_set().epoch(),
        Epoch::new(4)
    );
    // Its next outgoing epoch must decode under the cached contextual result,
    // rather than falling back to the v0 evidence decoder at runtime creation.
    let (next, _, _, next_binding, next_ancestry) =
        successor_evidence_variant(&successor_runtime, true, SuccessorBadSignature::None);
    let next_authority = decode_verify_successor_epoch_activation_strict_v1(
        successor_runtime.activation(),
        &next_ancestry,
        next.as_preimages(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(*next_authority.binding_ref().as_bytes(), next_binding);
    assert_eq!(
        StrictEpochRuntimeContextV1::from_activation_v1(next_authority)
            .unwrap()
            .activation()
            .new_validator_set()
            .epoch(),
        Epoch::new(5)
    );

    let mut recovery_budget = Cev0AdmissionBudgetV0::protocol_v0();
    let recovered = recover_successor_epoch_activation_authority_strict_v1(
        predecessor.activation(),
        &ancestry,
        evidence.as_preimages(),
        binding,
        &mut recovery_budget,
    )
    .unwrap();
    assert_eq!(*recovered.binding_ref().as_bytes(), binding);
    assert_eq!(recovery_budget.signature_work(), budget.signature_work());
    assert_eq!(
        StrictEpochRuntimeContextV1::from_activation_v1(recovered)
            .unwrap()
            .evidence_bytes(),
        &evidence
    );
    let mut wrong_binding = binding;
    wrong_binding[0] ^= 1;
    let mut failed_recovery = Cev0AdmissionBudgetV0::protocol_v0();
    assert!(recover_successor_epoch_activation_authority_strict_v1(
        predecessor.activation(),
        &ancestry,
        evidence.as_preimages(),
        wrong_binding,
        &mut failed_recovery,
    )
    .is_err());
    assert_eq!(failed_recovery.signature_work(), budget.signature_work());
}

#[test]
fn contextual_successor_rejects_every_signature_family_after_canonical_admission() {
    let predecessor = StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    for bad in [
        SuccessorBadSignature::ParentQc,
        SuccessorBadSignature::CheckpointQc,
        SuccessorBadSignature::Seal1Qc,
        SuccessorBadSignature::Seal2Qc,
        SuccessorBadSignature::CheckpointProposal,
        SuccessorBadSignature::Seal1Proposal,
        SuccessorBadSignature::Seal2Proposal,
        SuccessorBadSignature::CheckpointTimeout,
        SuccessorBadSignature::Seal1Timeout,
        SuccessorBadSignature::Seal2Timeout,
        SuccessorBadSignature::OldHandoff,
        SuccessorBadSignature::NewHandoff,
    ] {
        let (evidence, _, _, _, ancestry) = successor_evidence_variant(&predecessor, true, bad);
        let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
        let decoded = decode_epoch_activation_evidence_with_context_v1_exact(
            evidence.as_preimages(),
            predecessor.structural_context(),
            &mut measured,
        )
        .unwrap_or_else(|error| panic!("{bad:?} must remain structurally canonical: {error}"));
        derive_successor_epoch_joint_structure_v1(&decoded, predecessor.structural_context())
            .unwrap_or_else(|error| panic!("{bad:?} must preserve all joint relations: {error}"));
        assert!(measured.signature_work() > 0);
        let mut actual = Cev0AdmissionBudgetV0::protocol_v0();
        actual.charge_signature_work(7).unwrap();
        assert!(
            decode_verify_successor_epoch_activation_strict_v1(
                predecessor.activation(),
                &ancestry,
                evidence.as_preimages(),
                &mut actual,
            )
            .is_err(),
            "{bad:?} must fail strict cryptographic verification"
        );
        assert_eq!(
            actual.signature_work(),
            measured.signature_work() + 7,
            "{bad:?} must retain work reserved before signature verification"
        );
    }
}

#[test]
fn contextual_successor_binds_predecessor_ancestry_roots_and_exact_work_budget() {
    let predecessor = StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, _, _, _, ancestry) =
        successor_evidence_variant(&predecessor, true, SuccessorBadSignature::None);
    let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
    let successor = decode_verify_successor_epoch_activation_strict_v1(
        predecessor.activation(),
        &ancestry,
        evidence.as_preimages(),
        &mut measured,
    )
    .unwrap();
    let work = measured.signature_work();
    let mut wrong_context_budget = Cev0AdmissionBudgetV0::protocol_v0();
    assert!(decode_verify_successor_epoch_activation_strict_v1(
        &successor,
        &ancestry,
        evidence.as_preimages(),
        &mut wrong_context_budget,
    )
    .is_err());
    assert_eq!(wrong_context_budget.signature_work(), 0);

    for malformed in [
        Vec::new(),
        ancestry[..1].to_vec(),
        ancestry[1..].to_vec(),
        ancestry[..ancestry.len() - 1].to_vec(),
        vec![ancestry[0].clone(); 257],
        {
            let mut fork = ancestry.clone();
            fork.swap(1, 2);
            fork
        },
    ] {
        assert!(decode_verify_successor_epoch_activation_strict_v1(
            predecessor.activation(),
            &malformed,
            evidence.as_preimages(),
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err());
    }
    for field in 0..8 {
        let mut trailing = evidence.clone();
        let root = match field {
            0 => &mut trailing.old_checkpoint_finality,
            1 => &mut trailing.next_epoch_commitment,
            2 => &mut trailing.authorization_kernel,
            3 => &mut trailing.old_validator_set,
            4 => &mut trailing.old_consensus_parameters,
            5 => &mut trailing.new_validator_set,
            6 => &mut trailing.new_consensus_parameters,
            _ => &mut trailing.authenticated_checkpoint_parent_header,
        };
        root.push(0);
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        budget.charge_signature_work(7).unwrap();
        assert!(
            decode_verify_successor_epoch_activation_strict_v1(
                predecessor.activation(),
                &ancestry,
                trailing.as_preimages(),
                &mut budget,
            )
            .is_err(),
            "root {field} trailing bytes must reject"
        );
        assert_eq!(budget.signature_work(), 7, "structural rejection is atomic");
    }
    let maximum_root = Cev0AdmissionBudgetV0::protocol_v0().maximum_root_bytes();
    let mut exact = Cev0AdmissionBudgetV0::new(maximum_root, work + 7);
    exact.charge_signature_work(7).unwrap();
    assert!(decode_verify_successor_epoch_activation_strict_v1(
        predecessor.activation(),
        &ancestry,
        evidence.as_preimages(),
        &mut exact,
    )
    .is_ok());
    assert_eq!(exact.signature_work(), work + 7);
    let mut short = Cev0AdmissionBudgetV0::new(maximum_root, work + 6);
    short.charge_signature_work(7).unwrap();
    assert!(decode_verify_successor_epoch_activation_strict_v1(
        predecessor.activation(),
        &ancestry,
        evidence.as_preimages(),
        &mut short,
    )
    .is_err());
    assert_eq!(
        short.signature_work(),
        7,
        "failed structural work reservation must retain the caller's prior work"
    );
}

fn first_epoch_finality_for_context(context: &StrictEpochRuntimeContextV1) -> FinalityProofV0 {
    let activation = context.activation();
    let set = activation.new_validator_set();
    let params = activation.new_consensus_parameters();
    let terminal = activation.terminal_old_header();
    let first = header(
        set,
        BlockKind::EpochHandoff,
        1,
        terminal.height().get() + 1,
        terminal.id(),
        set.validators()[0].id(),
        StateRoot::new([81; 32]),
        None,
        terminal.timestamp_ms() + 1,
        false,
    );
    let first_qc = qc(set, &first);
    let authorization = context.structural_context().authorization();
    let root = ProposalWitnessV0::signing_root_for(
        &first,
        context.anchor_reference(),
        None,
        Some(authorization),
    )
    .unwrap();
    let signature = Signature64::from_array(
        signing_key(set.validator(first.proposer_id()).unwrap())
            .sign(root.as_bytes())
            .to_bytes(),
    );
    let first_certified = CertifiedHeaderV0::new(
        first.clone(),
        context.anchor_reference().clone(),
        None,
        Some(authorization.clone()),
        signature,
        first_qc.clone(),
        set,
        Some(activation.old_validator_set()),
        params,
        terminal.timestamp_ms(),
    )
    .unwrap();
    let child = header(
        set,
        BlockKind::Regular,
        2,
        first.height().get() + 1,
        first.id(),
        set.validators()[1].id(),
        StateRoot::new([82; 32]),
        None,
        first.timestamp_ms() + 1,
        false,
    );
    let child_qc = qc(set, &child);
    let grandchild = header(
        set,
        BlockKind::Regular,
        3,
        child.height().get() + 1,
        child.id(),
        set.validators()[2].id(),
        StateRoot::new([83; 32]),
        None,
        child.timestamp_ms() + 1,
        false,
    );
    FinalityProofV0::new(
        first_certified,
        certified(
            set,
            params,
            child.clone(),
            first_qc,
            first.timestamp_ms(),
            None,
            child_qc.clone(),
            false,
        ),
        certified(
            set,
            params,
            grandchild.clone(),
            child_qc,
            child.timestamp_ms(),
            None,
            qc(set, &grandchild),
            false,
        ),
        set,
        Some(activation.old_validator_set()),
        params,
        terminal.timestamp_ms(),
    )
    .unwrap()
}

#[test]
fn historical_path_crosses_contextual_successor_and_verifies_genuine_first_new_terminal() {
    use trnm_consensus_crypto::verify_historical_header_ancestry_v1;
    let predecessor = StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, _, _, binding, ancestry) =
        successor_evidence_variant(&predecessor, true, SuccessorBadSignature::None);
    let successor = decode_verify_successor_epoch_activation_strict_v1(
        predecessor.activation(),
        &ancestry,
        evidence.as_preimages(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let successor = StrictEpochRuntimeContextV1::from_activation_v1(successor).unwrap();
    let terminal = first_epoch_finality_for_context(&successor);
    let terminal_bytes = terminal.try_cev0_bytes().unwrap();
    // Anchor C28, original S29/S30, authenticated C31..C37, contextual
    // C38/S39/S40, then genuinely certified first-new C41 (proof C41..C43).
    let checkpoint = predecessor.activation().old_checkpoint_finality();
    let anchor = checkpoint.finalized_block().header();
    let mut headers = vec![
        checkpoint.child().header().clone(),
        checkpoint.grandchild().header().clone(),
    ];
    headers.extend_from_slice(&ancestry[1..]);
    let next = successor.activation().old_checkpoint_finality();
    headers.extend([
        next.finalized_block().header().clone(),
        next.child().header().clone(),
        next.grandchild().header().clone(),
        terminal.finalized_block().header().clone(),
    ]);
    assert_eq!(anchor.height().get(), 28);
    assert_eq!(headers.last().unwrap().height().get(), 41);
    let encoded = headers
        .iter()
        .map(|header| header.try_cev0_bytes().unwrap())
        .collect::<Vec<_>>();
    let refs = encoded.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let activations = [
        predecessor.evidence_bytes().as_preimages(),
        evidence.as_preimages(),
    ];
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let verified = verify_historical_header_ancestry_v1(
        anchor,
        predecessor.activation().old_validator_set(),
        predecessor.activation().old_consensus_parameters(),
        &refs,
        &activations,
        &terminal_bytes,
        HistoricalAncestryLimitsV1::default(),
        &mut budget,
    )
    .unwrap();
    assert_eq!(verified.headers(), headers);
    assert_eq!(verified.activations().len(), 2);
    assert_eq!(*verified.activations()[1].binding_ref().as_bytes(), binding);
    assert_eq!(verified.terminal_proof(), &terminal);
    assert_eq!(verified.terminal_header().height().get(), 41);
    assert_eq!(
        verified.terminal_validator_set(),
        successor.activation().new_validator_set()
    );
    assert!(budget.signature_work() > 0);

    let first_signature = terminal.finalized_block().proposer_signature().as_bytes();
    let mut corrupted = terminal_bytes.clone();
    let offset = corrupted
        .windows(64)
        .position(|bytes| bytes == first_signature)
        .unwrap();
    corrupted[offset] ^= 1;
    // The terminal is still canonical under the complete contextual activation;
    // the historical consumer must reject its signature and retain all charges.
    decode_epoch_runtime_finality_proof_v1_exact_with_budget(
        &corrupted,
        successor.structural_context(),
        successor.activation().terminal_old_header().timestamp_ms(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let mut failed_budget = Cev0AdmissionBudgetV0::protocol_v0();
    assert!(verify_historical_header_ancestry_v1(
        anchor,
        predecessor.activation().old_validator_set(),
        predecessor.activation().old_consensus_parameters(),
        &refs,
        &activations,
        &corrupted,
        HistoricalAncestryLimitsV1::default(),
        &mut failed_budget,
    )
    .is_err());
    assert_eq!(failed_budget.signature_work(), budget.signature_work());
    for index in [1, 2, ancestry.len(), headers.len() - 4] {
        let mut missing = refs.clone();
        missing.remove(index);
        assert!(
            verify_historical_header_ancestry_v1(
                anchor,
                predecessor.activation().old_validator_set(),
                predecessor.activation().old_consensus_parameters(),
                &missing,
                &activations,
                &terminal_bytes,
                HistoricalAncestryLimitsV1::default(),
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .is_err(),
            "missing header at index {index} must break the exact successor interval"
        );
    }
}

#[test]
fn successor_composition_rejects_genuine_v0_authority_with_repeated_ancestry_views() {
    let predecessor = StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, old_set, old_parameters, binding, ancestry) =
        successor_evidence_with_ancestry_variant(
            &predecessor,
            false,
            SuccessorBadSignature::None,
            true,
        );
    // The complete chain is rebuilt before checkpoint QCs, proposals and both
    // handoff roles are genuinely signed. This is not a broken-hash mutant.
    assert_eq!(
        ancestry.first(),
        Some(predecessor.activation().terminal_old_header())
    );
    for pair in ancestry.windows(2) {
        assert_eq!(pair[1].parent_id(), pair[0].id());
        assert_eq!(pair[1].height(), pair[0].height().checked_next().unwrap());
        assert_eq!(pair[1].validator_set_id(), old_set.id());
        assert_eq!(pair[1].consensus_parameters_hash(), old_parameters.hash());
    }
    assert_eq!(ancestry[1].block_kind(), BlockKind::EpochHandoff);
    assert_eq!(ancestry[2].block_kind(), BlockKind::Regular);
    assert_eq!(ancestry[1].view(), ancestry[2].view());
    let successor = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .expect("the original v0 checkpoint/two-seal/role signatures are valid");
    assert_eq!(
        ancestry.last(),
        Some(successor.authenticated_checkpoint_parent_header())
    );
    let successor = StrictEpochRuntimeContextV1::from_activation_v1(successor).unwrap();
    let error =
        StrictEpochRuntimeContextV1::compose_successor_v1(&predecessor, successor, &ancestry)
            .expect_err("signed checkpoint authority does not validate intermediate views");
    assert!(matches!(
        error,
        ValidationError::InvalidProposal("successor retained ancestry edge mismatch")
    ));

    let bounded_successor = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let bounded_successor =
        StrictEpochRuntimeContextV1::from_activation_v1(bounded_successor).unwrap();
    let mut oversized = vec![ancestry[0].clone(); 257];
    *oversized.last_mut().unwrap() = ancestry.last().unwrap().clone();
    assert!(matches!(
        StrictEpochRuntimeContextV1::compose_successor_v1(
            &predecessor,
            bounded_successor,
            &oversized,
        ),
        Err(ValidationError::InvalidProposal("retained ancestry count"))
    ));

    let mut structural = Cev0AdmissionBudgetV0::protocol_v0();
    decode_epoch_activation_evidence_with_context_v1_exact(
        evidence.as_preimages(),
        predecessor.structural_context(),
        &mut structural,
    )
    .unwrap();
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    budget.charge_signature_work(7).unwrap();
    let error = decode_verify_successor_epoch_activation_strict_v1(
        predecessor.activation(),
        &ancestry,
        evidence.as_preimages(),
        &mut budget,
    )
    .expect_err("both entrypoints apply the same historical-link rules");
    assert!(matches!(
        error,
        trnm_consensus_crypto::StrictSuccessorEpochActivationErrorV1::Consensus(
            ValidationError::InvalidEpochTransition("historical block geometry")
        )
    ));
    assert_eq!(budget.signature_work(), structural.signature_work() + 7);
}
