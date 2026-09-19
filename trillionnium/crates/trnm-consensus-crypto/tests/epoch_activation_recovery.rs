use serde_json::Value;
use trnm_consensus_crypto::{
    recover_epoch_activation_authority_strict_v0, EpochActivationRecoveryErrorV0,
};
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_epoch_activation_evidence_v0_exact,
    decode_validator_set_v0_exact, Cev0AdmissionBudgetV0, ConsensusParametersV0,
    EpochActivationEvidenceBytesV0, EpochActivationEvidencePreimagesV0, ValidatorSet,
};

const CORPUS: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json"
);

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

fn fixture(
    profile: &str,
) -> (
    EpochActivationEvidenceBytesV0,
    ValidatorSet,
    ConsensusParametersV0,
    [u8; 32],
) {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let case = &corpus[profile];
    let raw = |section: &str, field: &str| unhex(case[section][field].as_str().unwrap());
    let bytes = EpochActivationEvidenceBytesV0 {
        old_checkpoint_finality: raw("checkpoint_finality", "raw_finality_proof_cev0_hex"),
        next_epoch_commitment: raw("preheader", "commitment_cev0_hex"),
        authorization_kernel: raw("handoff", "raw_anchor_certificate_kernel_cev0_hex"),
        old_validator_set: raw("preheader", "old_validator_set_cev0_hex"),
        old_consensus_parameters: raw("preheader", "old_parameters_cev0_hex"),
        new_validator_set: raw("preheader", "new_validator_set_cev0_hex"),
        new_consensus_parameters: raw("preheader", "new_parameters_cev0_hex"),
        authenticated_checkpoint_parent_header: raw(
            "preheader",
            "checkpoint_parent_header_cev0_hex",
        ),
    };
    let old_set = decode_validator_set_v0_exact(&bytes.old_validator_set).unwrap();
    let old_parameters =
        decode_consensus_parameters_v0_exact(&bytes.old_consensus_parameters).unwrap();
    let binding = unhex(match profile {
        "positive" => "4ba70b831d3bd70a1be8669f654ac42148017fca0b83f84e999ac532b9c70e4f",
        "authenticated_fallback" => {
            "3f719cc7d84539da791a3206d46c4d529f390b2333c35128847f7b62dcd2fc73"
        }
        _ => panic!("unknown frozen fixture"),
    })
    .try_into()
    .unwrap();
    (bytes, old_set, old_parameters, binding)
}

fn roots(fields: EpochActivationEvidencePreimagesV0<'_>) -> [&[u8]; 8] {
    [
        fields.old_checkpoint_finality,
        fields.next_epoch_commitment,
        fields.authorization_kernel,
        fields.old_validator_set,
        fields.old_consensus_parameters,
        fields.new_validator_set,
        fields.new_consensus_parameters,
        fields.authenticated_checkpoint_parent_header,
    ]
}

fn root_mut(fields: &mut EpochActivationEvidenceBytesV0, index: usize) -> &mut Vec<u8> {
    match index {
        0 => &mut fields.old_checkpoint_finality,
        1 => &mut fields.next_epoch_commitment,
        2 => &mut fields.authorization_kernel,
        3 => &mut fields.old_validator_set,
        4 => &mut fields.old_consensus_parameters,
        5 => &mut fields.new_validator_set,
        6 => &mut fields.new_consensus_parameters,
        7 => &mut fields.authenticated_checkpoint_parent_header,
        _ => panic!("invalid component"),
    }
}

#[test]
fn exact_persisted_preimages_rebuild_strict_authority_and_roundtrip_each_frozen_root() {
    for profile in ["positive", "authenticated_fallback"] {
        let (bytes, old_set, old_parameters, binding) = fixture(profile);
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        let decoded = decode_epoch_activation_evidence_v0_exact(
            bytes.as_preimages(),
            &old_set,
            &old_parameters,
            &mut budget,
        )
        .unwrap();
        let reencoded = decoded.canonical_preimages_v0().unwrap();
        assert_eq!(roots(bytes.as_preimages()), roots(reencoded.as_preimages()));
        assert!(budget.signature_work() > 0);
        for _ in 0..2 {
            let authority = recover_epoch_activation_authority_strict_v0(
                reencoded.as_preimages(),
                &old_set,
                &old_parameters,
                binding,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
            assert_eq!(authority.binding_ref().as_bytes(), &binding);
            assert_eq!(authority.old_validator_set(), &old_set);
            assert_eq!(authority.old_consensus_parameters(), &old_parameters);
            assert_eq!(
                authority.authenticated_checkpoint_parent_header(),
                decoded.authenticated_checkpoint_parent_header()
            );
            assert_eq!(
                authority.old_checkpoint_finality(),
                decoded.old_checkpoint_finality()
            );
        }
    }
}

#[test]
fn every_nested_root_requires_exact_exhaustion_and_failure_preserves_budget() {
    let (bytes, old_set, old_parameters, binding) = fixture("positive");
    for index in 0..8 {
        let mut changed = bytes.clone();
        root_mut(&mut changed, index).push(0);
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        budget.charge_signature_work(1).unwrap();
        let before = budget;
        assert!(
            recover_epoch_activation_authority_strict_v0(
                changed.as_preimages(),
                &old_set,
                &old_parameters,
                binding,
                &mut budget,
            )
            .is_err(),
            "component {index} accepted trailing bytes"
        );
        assert_eq!(budget, before);
    }
}

#[test]
fn valid_cross_bundle_component_substitution_cannot_recreate_the_pinned_authority() {
    let (bytes, old_set, old_parameters, binding) = fixture("positive");
    let (other, _, _, _) = fixture("authenticated_fallback");
    let mut distinct = 0;
    for index in 0..8 {
        let alternate = roots(other.as_preimages())[index];
        if alternate == roots(bytes.as_preimages())[index] {
            continue;
        }
        distinct += 1;
        let mut changed = bytes.clone();
        *root_mut(&mut changed, index) = alternate.to_vec();
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        let before = budget;
        assert!(
            recover_epoch_activation_authority_strict_v0(
                changed.as_preimages(),
                &old_set,
                &old_parameters,
                binding,
                &mut budget,
            )
            .is_err(),
            "component {index} accepted a foreign exact preimage"
        );
        assert_eq!(budget, before);
    }
    assert_eq!(
        distinct, 4,
        "the corpus shares exactly its four configuration roots"
    );
}

#[test]
fn independent_old_context_and_expected_binding_are_mandatory() {
    let (bytes, old_set, old_parameters, binding) = fixture("positive");
    let foreign_set = decode_validator_set_v0_exact(&bytes.new_validator_set).unwrap();
    let mut changed_parameters = old_parameters.fields();
    changed_parameters.max_block_time_step_ms += 1;
    let foreign_parameters = ConsensusParametersV0::new(changed_parameters).unwrap();
    for (set, parameters) in [
        (&foreign_set, &old_parameters),
        (&old_set, &foreign_parameters),
    ] {
        assert!(recover_epoch_activation_authority_strict_v0(
            bytes.as_preimages(),
            set,
            parameters,
            binding,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .is_err());
    }
    for expected in [[0; 32], [0xee; 32]] {
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        let before = budget;
        let failure = recover_epoch_activation_authority_strict_v0(
            bytes.as_preimages(),
            &old_set,
            &old_parameters,
            expected,
            &mut budget,
        )
        .unwrap_err();
        assert!(matches!(
            failure,
            EpochActivationRecoveryErrorV0::ZeroExpectedBinding
                | EpochActivationRecoveryErrorV0::BindingMismatch
        ));
        if expected == [0; 32] {
            assert_eq!(budget, before);
        } else {
            assert!(budget.signature_work() > before.signature_work());
        }
    }
}

#[test]
fn shape_valid_handoff_signature_corruption_spends_work_and_exhausts_exact_budget() {
    let (mut bytes, old_set, old_parameters, binding) = fixture("positive");
    let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
    recover_epoch_activation_authority_strict_v0(
        bytes.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut measured,
    )
    .unwrap();
    *bytes.authorization_kernel.last_mut().unwrap() ^= 1;
    let mut budget =
        Cev0AdmissionBudgetV0::new(measured.maximum_root_bytes(), measured.signature_work());
    let failure = recover_epoch_activation_authority_strict_v0(
        bytes.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut budget,
    )
    .unwrap_err();
    assert!(
        matches!(failure, EpochActivationRecoveryErrorV0::Verification(_)),
        "{failure}"
    );
    assert_eq!(budget.signature_work(), measured.signature_work());
    let charged = budget;
    let retry = recover_epoch_activation_authority_strict_v0(
        bytes.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut budget,
    )
    .unwrap_err();
    assert!(
        matches!(retry, EpochActivationRecoveryErrorV0::Evidence(_)),
        "budget must reject before a second strict verification: {retry}"
    );
    assert_eq!(budget, charged);
}

#[test]
fn aggregate_bytes_and_signature_work_are_checked_at_the_exact_boundary() {
    let (bytes, old_set, old_parameters, binding) = fixture("positive");
    let total_bytes: usize = roots(bytes.as_preimages())
        .iter()
        .map(|root| root.len())
        .sum();
    let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
    recover_epoch_activation_authority_strict_v0(
        bytes.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut measured,
    )
    .unwrap();
    let work = measured.signature_work();
    for (byte_limit, work_limit) in [(total_bytes - 1, work), (total_bytes, work - 1)] {
        let mut budget = Cev0AdmissionBudgetV0::new(byte_limit, work_limit);
        let before = budget;
        assert!(recover_epoch_activation_authority_strict_v0(
            bytes.as_preimages(),
            &old_set,
            &old_parameters,
            binding,
            &mut budget,
        )
        .is_err());
        assert_eq!(budget, before);
    }
    let mut exact = Cev0AdmissionBudgetV0::new(total_bytes, work);
    recover_epoch_activation_authority_strict_v0(
        bytes.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut exact,
    )
    .unwrap();
    assert_eq!(exact.signature_work(), work);
}

#[test]
fn strict_first_epoch_header_binds_recovered_authority_and_preserves_it_on_rejection() {
    use ed25519_dalek::{Signer, SigningKey};
    use trnm_consensus_crypto::verify_first_epoch_proposal_header_strict_v0;
    use trnm_consensus_types::{
        epoch_first_proposal_signing_root_v0, BlockHeader, BlockKind, EvidenceRoot, PayloadDigest,
        ReceiptsRoot, SignatureBytes, StateRoot, View,
    };
    let (bytes, old_set, old_parameters, binding) = fixture("positive");
    let activation = recover_epoch_activation_authority_strict_v0(
        bytes.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let new_set = activation.new_validator_set();
    let proposer = &new_set.validators()[0];
    // Reproduce the published corpus authoring fixture's deterministic seed;
    // this test-only domain is not a production custody derivation.
    use sha2::{Digest, Sha256};
    let mut seed = Sha256::new();
    seed.update(b"trnm.poco-bft.checkpoint-finality.private-fixture.v0:");
    seed.update(proposer.id().as_bytes());
    let key = SigningKey::from_bytes(&seed.finalize().into());
    assert_eq!(
        key.verifying_key().to_bytes(),
        proposer.consensus_key().into_bytes()
    );
    let descriptor = activation.handoff_certificate().descriptor().fields();
    let header = BlockHeader::new(
        new_set.genesis_hash(),
        new_set.chain_id(),
        new_set.protocol_version(),
        new_set.epoch(),
        View::new(1),
        descriptor.activation_height,
        BlockKind::EpochHandoff,
        descriptor.terminal_old_block_id,
        proposer.id(),
        new_set.id(),
        activation.new_consensus_parameters().hash(),
        PayloadDigest::new([0x41; 32]),
        StateRoot::new([0x42; 32]),
        ReceiptsRoot::new([0x43; 32]),
        EvidenceRoot::new([0x44; 32]),
        activation.terminal_old_header().timestamp_ms() + 1,
        None,
    )
    .unwrap();
    let root = epoch_first_proposal_signing_root_v0(
        &header,
        activation.authorization_kernel(),
        &old_set,
        new_set,
        activation.new_consensus_parameters(),
    )
    .unwrap();
    let signature = SignatureBytes::from_array(key.sign(root.as_bytes()).to_bytes());
    let verified = verify_first_epoch_proposal_header_strict_v0(
        &activation,
        header.clone(),
        signature,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(verified.activation_binding_v0(), binding);
    assert_eq!(verified.header_v0(), &header);
    assert_eq!(verified.signing_root_v0(), root);

    let mut bad = *signature.as_bytes();
    bad[0] ^= 1;
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let before = budget;
    assert!(verify_first_epoch_proposal_header_strict_v0(
        &activation,
        header.clone(),
        SignatureBytes::from_array(bad),
        &mut budget,
    )
    .is_err());
    assert_eq!(budget.signature_work(), before.signature_work() + 1);
    let charged = budget;
    let (foreign_bytes, foreign_set, foreign_parameters, foreign_binding) =
        fixture("authenticated_fallback");
    let foreign = recover_epoch_activation_authority_strict_v0(
        foreign_bytes.as_preimages(),
        &foreign_set,
        &foreign_parameters,
        foreign_binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert!(verify_first_epoch_proposal_header_strict_v0(
        &foreign,
        header.clone(),
        signature,
        &mut budget,
    )
    .is_err());
    assert_eq!(budget, charged);
    let skipped = BlockHeader::new(
        header.genesis_hash(),
        header.chain_id(),
        header.protocol_version(),
        header.epoch(),
        View::new(2),
        header.height(),
        header.block_kind(),
        header.parent_id(),
        new_set.validators()[1].id(),
        header.validator_set_id(),
        header.consensus_parameters_hash(),
        header.payload_digest(),
        header.state_root(),
        header.receipts_root(),
        header.evidence_root(),
        header.timestamp_ms(),
        None,
    )
    .unwrap();
    assert!(
        verify_first_epoch_proposal_header_strict_v0(&activation, skipped, signature, &mut budget,)
            .is_err(),
        "a skipped view requires a dedicated complete TC path"
    );
    assert_eq!(budget, charged);
    let mut exact_budget = Cev0AdmissionBudgetV0::new(1_000_000, 1);
    assert!(verify_first_epoch_proposal_header_strict_v0(
        &activation,
        header.clone(),
        SignatureBytes::from_array(bad),
        &mut exact_budget,
    )
    .is_err());
    assert_eq!(exact_budget.signature_work(), 1);
    let retry = verify_first_epoch_proposal_header_strict_v0(
        &activation,
        header.clone(),
        signature,
        &mut exact_budget,
    )
    .unwrap_err();
    assert!(matches!(
        retry,
        trnm_consensus_types::ValidationError::InvalidProposal(
            "first epoch header exceeds admission signature-work limit"
        )
    ));
    verify_first_epoch_proposal_header_strict_v0(&activation, header, signature, &mut budget)
        .expect("invalid peer proposals do not consume or poison the exact authority");
}

#[test]
fn pre_handoff_context_authenticates_both_configurations_before_any_role_signature() {
    use trnm_consensus_crypto::verify_pre_handoff_context_strict_v1;
    use trnm_consensus_types::{HandoffDescriptorV0, StateRoot, View};
    for profile in ["positive", "authenticated_fallback"] {
        let (bytes, old_set, old_parameters, _) = fixture(profile);
        let decoded = decode_epoch_activation_evidence_v0_exact(
            bytes.as_preimages(),
            &old_set,
            &old_parameters,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
        let descriptor = decoded
            .authorization_kernel()
            .handoff_certificate()
            .descriptor();
        let verify = |descriptor: &HandoffDescriptorV0| {
            verify_pre_handoff_context_strict_v1(
                decoded.old_checkpoint_finality(),
                decoded.next_epoch_commitment(),
                descriptor,
                decoded.old_validator_set(),
                decoded.old_consensus_parameters(),
                decoded.new_validator_set(),
                decoded.new_consensus_parameters(),
                decoded.authenticated_checkpoint_parent_header(),
            )
        };
        // This API never accepts a certificate or either handoff signature;
        // it can therefore be used by the actual producer of the first share.
        let context = verify(descriptor).unwrap();
        assert_eq!(context.descriptor(), descriptor);
        assert_eq!(context.old_validator_set(), &old_set);
        assert_eq!(context.new_validator_set(), decoded.new_validator_set());
        assert_eq!(
            context.checkpoint_parent_block_id(),
            decoded.authenticated_checkpoint_parent_header().id()
        );
        assert_eq!(
            context.binding_ref(),
            verify(descriptor).unwrap().binding_ref()
        );
        assert_ne!(context.binding_ref(), [0; 32]);
        let mut fields = descriptor.fields().clone();
        fields.terminal_old_view = View::new(fields.terminal_old_view.get() + 1);
        assert!(verify(&HandoffDescriptorV0::new(fields).unwrap()).is_err());
        let mut fields = descriptor.fields().clone();
        fields.checkpoint_state_root = StateRoot::new([0xab; 32]);
        assert!(verify(&HandoffDescriptorV0::new(fields).unwrap()).is_err());
        assert!(verify_pre_handoff_context_strict_v1(
            decoded.old_checkpoint_finality(),
            decoded.next_epoch_commitment(),
            descriptor,
            decoded.new_validator_set(),
            decoded.old_consensus_parameters(),
            decoded.old_validator_set(),
            decoded.new_consensus_parameters(),
            decoded.authenticated_checkpoint_parent_header(),
        )
        .is_err());
    }
}

fn first_epoch_finality_bytes(
    activation: &trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0,
) -> (
    Vec<u8>,
    trnm_consensus_crypto::FinalityExpectationV0,
    Vec<usize>,
) {
    first_epoch_finality_with_views(activation, [1, 2, 3], None)
}

fn first_epoch_finality_with_views(
    activation: &trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0,
    views: [u64; 3],
    anchor_context: Option<(
        trnm_consensus_types::QcReferenceV0,
        trnm_consensus_types::EpochAnchorAuthorizationV0,
    )>,
) -> (
    Vec<u8>,
    trnm_consensus_crypto::FinalityExpectationV0,
    Vec<usize>,
) {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use trnm_consensus_types::*;
    let set = activation.new_validator_set();
    let params = activation.new_consensus_parameters();
    let key = |validator: &Validator| {
        let mut h = Sha256::new();
        h.update(b"trnm.poco-bft.checkpoint-finality.private-fixture.v0:");
        h.update(validator.id().as_bytes());
        let key = SigningKey::from_bytes(&h.finalize().into());
        assert_eq!(
            key.verifying_key().to_bytes(),
            validator.consensus_key().into_bytes()
        );
        key
    };
    let common = || {
        let mut bytes = 0u16.to_be_bytes().to_vec();
        bytes.extend(set.genesis_hash().as_bytes());
        bytes.extend((set.chain_id().as_bytes().len() as u16).to_be_bytes());
        bytes.extend(set.chain_id().as_bytes());
        bytes.extend(set.protocol_version().get().to_be_bytes());
        bytes.extend(set.epoch().get().to_be_bytes());
        bytes.extend(set.id().as_bytes());
        bytes
    };
    let mut encoded = common();
    encoded.extend(params.hash().as_bytes());
    let terminal = activation.terminal_old_header();
    let mut anchor = common();
    anchor.extend(0u64.to_be_bytes());
    anchor.extend(terminal.height().get().to_be_bytes());
    anchor.extend(terminal.id().as_bytes());
    anchor.extend(0u32.to_be_bytes());
    let mut parent_id = terminal.id();
    let mut previous_qc = None;
    let mut expected = None;
    let mut signature_offsets = Vec::new();
    for (index, view) in views.into_iter().enumerate() {
        let height_offset = index as u64 + 1;
        let proposer = &set.validators()[(view as usize - 1) % set.validators().len()];
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(view),
            Height::new(terminal.height().get() + height_offset),
            if index == 0 {
                BlockKind::EpochHandoff
            } else {
                BlockKind::Regular
            },
            parent_id,
            proposer.id(),
            set.id(),
            params.hash(),
            PayloadDigest::new([0x41; 32]),
            StateRoot::new([0x42; 32]),
            ReceiptsRoot::new([0x43; 32]),
            EvidenceRoot::new([0x44; 32]),
            terminal.timestamp_ms() + height_offset,
            None,
        )
        .unwrap();
        let justify_for_timeout = if index == 0 {
            anchor_context.as_ref().map(|(anchor, _)| anchor.clone())
        } else {
            Some(QcReferenceV0::ordinary(previous_qc.clone().unwrap()))
        };
        let timeout = if let Some(justify) = justify_for_timeout {
            if justify.qc_ref().view().get() + 1 < view {
                let entries = set
                    .validators()
                    .iter()
                    .map(|validator| {
                        let root = TimeoutVote::signing_root_for_set(
                            set,
                            View::new(view - 1),
                            justify.qc_ref(),
                        )
                        .unwrap();
                        TimeoutEntryV0::new(
                            validator.id(),
                            justify.qc_ref(),
                            SignatureBytes::from_array(
                                key(validator).sign(root.as_bytes()).to_bytes(),
                            ),
                        )
                        .unwrap()
                    })
                    .collect();
                Some(
                    TimeoutCertificateV0::new(
                        View::new(view - 1),
                        entries,
                        vec![justify.clone()],
                        justify.id(),
                        set,
                    )
                    .unwrap(),
                )
            } else {
                None
            }
        } else {
            None
        };
        let root =
            Vote::signing_root_for_set(set, header.view(), header.height(), header.id()).unwrap();
        let votes = set
            .validators()
            .iter()
            .map(|validator| {
                Vote::new(
                    set.chain_id(),
                    set.protocol_version(),
                    set.epoch(),
                    header.view(),
                    header.height(),
                    header.id(),
                    set.id(),
                    validator.id(),
                    SignatureBytes::from_array(key(validator).sign(root.as_bytes()).to_bytes()),
                    set,
                )
                .unwrap()
            })
            .collect();
        let qc = QuorumCertificate::new(
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
        .unwrap();
        if index == 0 {
            let root = if let Some((anchor, authorization)) = &anchor_context {
                ProposalWitnessV0::signing_root_for(
                    &header,
                    anchor,
                    timeout.as_ref(),
                    Some(authorization),
                )
                .unwrap()
            } else {
                epoch_first_proposal_signing_root_v0(
                    &header,
                    activation.authorization_kernel(),
                    activation.old_validator_set(),
                    set,
                    params,
                )
                .unwrap()
            };
            let signature = key(proposer).sign(root.as_bytes()).to_bytes();
            encoded.extend(header.try_cev0_bytes().unwrap());
            encoded.extend(&anchor);
            if let Some(tc) = &timeout {
                encoded.push(1);
                encoded.extend(tc.try_cev0_bytes().unwrap());
            } else {
                encoded.push(0);
            }
            encoded.push(1); // exact authorization follows
            encoded.extend(activation.authorization_cev0_bytes().unwrap());
            signature_offsets.push(encoded.len());
            encoded.extend(signature);
            encoded.extend(qc.try_cev0_bytes().unwrap());
            expected = Some(trnm_consensus_crypto::FinalityExpectationV0 {
                block_id: header.id(),
                height: header.height(),
                state_root: header.state_root(),
                receipts_root: header.receipts_root(),
                evidence_root: header.evidence_root(),
                parent_id: terminal.id(),
                parent_height: terminal.height(),
                parent_timestamp_ms: terminal.timestamp_ms(),
            });
        } else {
            let justify = QcReferenceV0::ordinary(previous_qc.take().unwrap());
            let witness = ProposalWitnessV0::new(
                &header,
                justify.clone(),
                timeout.clone(),
                None,
                SignatureBytes::from_array([1; 64]),
                set,
                None,
                params,
                header.timestamp_ms() - 1,
            )
            .unwrap();
            let root = witness.signing_root_for_header(&header).unwrap();
            let signature =
                SignatureBytes::from_array(key(proposer).sign(root.as_bytes()).to_bytes());
            let certified = CertifiedHeaderV0::new(
                header.clone(),
                justify,
                timeout,
                None,
                signature,
                qc.clone(),
                set,
                None,
                params,
                header.timestamp_ms() - 1,
            )
            .unwrap();
            let raw = certified.try_cev0_bytes().unwrap();
            let signature_position = raw
                .windows(64)
                .position(|x| x == signature.as_bytes())
                .unwrap();
            signature_offsets.push(encoded.len() + signature_position);
            encoded.extend(raw);
        }
        parent_id = header.id();
        previous_qc = Some(qc);
    }
    (encoded, expected.unwrap(), signature_offsets)
}

#[test]
fn first_epoch_finality_has_real_signatures_exact_decoding_and_oldest_target() {
    use trnm_consensus_crypto::{
        decode_verify_epoch_first_finality_strict_v1, decode_verify_finality_proof_strict_v0,
        POCO_THREE_CHAIN_PROOF_CLASS_V0,
    };
    let (evidence, old_set, old_parameters, binding) = fixture("positive");
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let (bytes, expected, signatures) = first_epoch_finality_bytes(&activation);
    let verify = |raw: &[u8], expected| {
        decode_verify_epoch_first_finality_strict_v1(
            evidence.as_preimages(),
            raw,
            &old_set,
            &old_parameters,
            expected,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
    };
    let verified = verify(&bytes, expected).unwrap();
    assert_eq!(verified.finalized_block_id(), expected.block_id);
    assert_eq!(verified.proof().try_cev0_bytes().unwrap(), bytes);
    assert!(decode_verify_finality_proof_strict_v0(
        POCO_THREE_CHAIN_PROOF_CLASS_V0,
        &bytes,
        activation.new_validator_set(),
        activation.new_consensus_parameters(),
        expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0()
    )
    .is_err());
    for offset in signatures {
        let mut corrupted = bytes.clone();
        corrupted[offset] ^= 1;
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        assert!(decode_verify_epoch_first_finality_strict_v1(
            evidence.as_preimages(),
            &corrupted,
            &old_set,
            &old_parameters,
            expected,
            &mut budget
        )
        .is_err());
        assert!(budget.signature_work() > 0);
    }
    for end in [0, 1, bytes.len() / 2, bytes.len() - 1] {
        assert!(verify(&bytes[..end], expected).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(verify(&trailing, expected).is_err());
    let mut wrong = expected;
    wrong.block_id = verified.proof().grandchild().header().id();
    assert!(verify(&bytes, wrong).is_err());
    wrong = expected;
    wrong.parent_timestamp_ms += 1;
    assert!(verify(&bytes, wrong).is_err());
    let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
    decode_verify_epoch_first_finality_strict_v1(
        evidence.as_preimages(),
        &bytes,
        &old_set,
        &old_parameters,
        expected,
        &mut measured,
    )
    .unwrap();
    let mut short =
        Cev0AdmissionBudgetV0::new(measured.maximum_root_bytes(), measured.signature_work() - 1);
    assert!(decode_verify_epoch_first_finality_strict_v1(
        evidence.as_preimages(),
        &bytes,
        &old_set,
        &old_parameters,
        expected,
        &mut short
    )
    .is_err());
    let mut exact =
        Cev0AdmissionBudgetV0::new(measured.maximum_root_bytes(), measured.signature_work());
    decode_verify_epoch_first_finality_strict_v1(
        evidence.as_preimages(),
        &bytes,
        &old_set,
        &old_parameters,
        expected,
        &mut exact,
    )
    .unwrap();
}

#[test]
fn skipped_epoch_views_require_and_verify_every_timeout_signature() {
    use trnm_consensus_crypto::decode_verify_epoch_first_finality_strict_v1;
    let (evidence, old_set, old_parameters, binding) = fixture("positive");
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let (base, expected, _) = first_epoch_finality_bytes(&activation);
    let verified = decode_verify_epoch_first_finality_strict_v1(
        evidence.as_preimages(),
        &base,
        &old_set,
        &old_parameters,
        expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let first = verified.proof().finalized_block();
    let anchor_context = (
        first.justify_qc().clone(),
        first.epoch_anchor_authorization().unwrap().clone(),
    );
    let (bytes, expected, _) =
        first_epoch_finality_with_views(&activation, [3, 5, 8], Some(anchor_context));
    let verify = |bytes: &[u8]| {
        decode_verify_epoch_first_finality_strict_v1(
            evidence.as_preimages(),
            bytes,
            &old_set,
            &old_parameters,
            expected,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
    };
    let verified = verify(&bytes).unwrap();
    assert_eq!(verified.proof().finalized_block().header().view().get(), 3);
    assert_eq!(verified.proof().grandchild().header().view().get(), 8);
    for certified in [
        verified.proof().finalized_block(),
        verified.proof().child(),
        verified.proof().grandchild(),
    ] {
        let tc = certified.timeout_certificate().unwrap();
        for entry in tc.entries() {
            let offset = bytes
                .windows(64)
                .position(|window| window == entry.signature().as_bytes())
                .unwrap();
            let mut corrupt = bytes.clone();
            corrupt[offset] ^= 1;
            assert!(verify(&corrupt).is_err());
        }
    }
}

#[test]
fn complete_first_proposal_strictly_binds_payload_and_tc_before_first_block() {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use trnm_consensus_crypto::{
        decode_verify_epoch_first_finality_strict_v1, verify_first_epoch_proposal_strict_v1,
    };
    use trnm_consensus_types::*;
    let (evidence, old_set, old_params, binding) = fixture("positive");
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let (raw, expected, _) = first_epoch_finality_bytes(&activation);
    let base = decode_verify_epoch_first_finality_strict_v1(
        evidence.as_preimages(),
        &raw,
        &old_set,
        &old_params,
        expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let first = base.proof().finalized_block();
    let context = (
        first.justify_qc().clone(),
        first.epoch_anchor_authorization().unwrap().clone(),
    );
    for views in [[1, 2, 3], [3, 5, 8]] {
        let (raw, expected, _) =
            first_epoch_finality_with_views(&activation, views, Some(context.clone()));
        let proof = decode_verify_epoch_first_finality_strict_v1(
            evidence.as_preimages(),
            &raw,
            &old_set,
            &old_params,
            expected,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
        let source = proof.proof().finalized_block();
        let h = source.header();
        let payload =
            ApplicationPayloadV0::new(vec![b"real first transaction bytes".to_vec()]).unwrap();
        let body = BlockBodyV0::new(payload, Vec::new()).unwrap();
        let header = BlockHeader::new(
            h.genesis_hash(),
            h.chain_id(),
            h.protocol_version(),
            h.epoch(),
            h.view(),
            h.height(),
            h.block_kind(),
            h.parent_id(),
            h.proposer_id(),
            h.validator_set_id(),
            h.consensus_parameters_hash(),
            body.payload_root().unwrap(),
            h.state_root(),
            h.receipts_root(),
            body.evidence_root().unwrap(),
            h.timestamp_ms(),
            None,
        )
        .unwrap();
        let set = activation.new_validator_set();
        let params = activation.new_consensus_parameters();
        let mut seed = Sha256::new();
        seed.update(b"trnm.poco-bft.checkpoint-finality.private-fixture.v0:");
        seed.update(header.proposer_id().as_bytes());
        let key = SigningKey::from_bytes(&seed.finalize().into());
        let make = |payload: Vec<u8>, bad_signature: bool| {
            let root = ProposalWitnessV0::signing_root_for(
                &header,
                source.justify_qc(),
                source.timeout_certificate(),
                source.epoch_anchor_authorization(),
            )
            .unwrap();
            let mut signature = key.sign(root.as_bytes()).to_bytes();
            if bad_signature {
                signature[0] ^= 1;
            }
            let witness = ProposalWitnessV0::new(
                &header,
                source.justify_qc().clone(),
                source.timeout_certificate().cloned(),
                source.epoch_anchor_authorization().cloned(),
                Signature64::from_array(signature),
                set,
                Some(&old_set),
                params,
                activation.terminal_old_header().timestamp_ms(),
            )
            .unwrap();
            SignedProposalV0::new(
                Block::new(header.clone(), payload, Vec::new()).unwrap(),
                witness,
                set,
                Some(&old_set),
                params,
                activation.terminal_old_header().timestamp_ms(),
            )
            .unwrap()
        };
        let payload = body.application_payload().try_cev0_bytes().unwrap();
        let valid = make(payload.clone(), false);
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        let verified =
            verify_first_epoch_proposal_strict_v1(&activation, valid.clone(), &mut budget).unwrap();
        assert_eq!(verified.proposal(), &valid);
        assert_eq!(verified.body().transaction_count(), 1);
        assert_eq!(verified.activation_binding(), binding);
        assert_eq!(
            budget.signature_work(),
            1 + source
                .timeout_certificate()
                .map_or(0, |tc| tc.entries().len())
        );
        let short = budget.signature_work() - 1;
        assert!(verify_first_epoch_proposal_strict_v1(
            &activation,
            valid,
            &mut Cev0AdmissionBudgetV0::new(budget.maximum_root_bytes(), short)
        )
        .is_err());
        assert!(verify_first_epoch_proposal_strict_v1(
            &activation,
            make(
                ApplicationPayloadV0::new(vec![b"substituted transaction".to_vec()])
                    .unwrap()
                    .try_cev0_bytes()
                    .unwrap(),
                false
            ),
            &mut Cev0AdmissionBudgetV0::protocol_v0()
        )
        .is_err());
        let mut bad_budget = Cev0AdmissionBudgetV0::protocol_v0();
        assert!(verify_first_epoch_proposal_strict_v1(
            &activation,
            make(payload, true),
            &mut bad_budget
        )
        .is_err());
        assert_eq!(bad_budget.signature_work(), budget.signature_work());
    }
}

#[test]
fn strict_runtime_context_admits_only_its_complete_epoch_and_exact_budgets() {
    use trnm_consensus_crypto::{
        decode_verify_epoch_first_finality_strict_v1, StrictEpochRuntimeContextV1,
    };
    let (evidence, old_set, old_parameters, binding) = fixture("positive");
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let (first, expected, _) = first_epoch_finality_bytes(&activation);
    let initial = decode_verify_epoch_first_finality_strict_v1(
        evidence.as_preimages(),
        &first,
        &old_set,
        &old_parameters,
        expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let source = initial.proof().finalized_block();
    let (raw, _, _) = first_epoch_finality_with_views(
        &activation,
        [3, 5, 8],
        Some((
            source.justify_qc().clone(),
            source.epoch_anchor_authorization().unwrap().clone(),
        )),
    );
    let parent_time = activation.terminal_old_header().timestamp_ms();
    let old_qc = activation.terminal_old_qc().try_cev0_bytes().unwrap();
    let runtime = StrictEpochRuntimeContextV1::from_activation_v1(activation).unwrap();
    assert_eq!(runtime.evidence_bytes(), &evidence);
    assert_eq!(runtime.anchor_reference(), source.justify_qc());
    let proof = runtime
        .decode_verify_finality_v1(&raw, parent_time, &mut Cev0AdmissionBudgetV0::protocol_v0())
        .unwrap();
    assert_eq!(proof.finalized_block().header().view().get(), 3);
    for certified in [proof.finalized_block(), proof.child(), proof.grandchild()] {
        let tc = certified.timeout_certificate().unwrap();
        let tc_raw = tc.try_cev0_bytes().unwrap();
        let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
        assert_eq!(
            runtime
                .decode_verify_timeout_certificate_v1(&tc_raw, &mut measured)
                .unwrap(),
            *tc
        );
        assert!(runtime
            .decode_verify_timeout_certificate_v1(
                &tc_raw,
                &mut Cev0AdmissionBudgetV0::new(tc_raw.len(), measured.signature_work() - 1)
            )
            .is_err());
        let mut corrupt = tc_raw.clone();
        let signature = tc.entries()[0].signature().as_bytes();
        let offset = corrupt
            .windows(64)
            .position(|window| window == signature)
            .unwrap();
        corrupt[offset] ^= 1;
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        assert!(runtime
            .decode_verify_timeout_certificate_v1(&corrupt, &mut budget)
            .is_err());
        assert_eq!(budget.signature_work(), measured.signature_work());
        for reference in tc.referenced_qcs() {
            let bytes = match reference {
                trnm_consensus_types::QcReferenceV0::Ordinary(qc) => qc.try_cev0_bytes().unwrap(),
                trnm_consensus_types::QcReferenceV0::Synthetic(qc) => match qc.as_ref() {
                    trnm_consensus_types::ContextAuthorizedQcV0::Genesis(qc) => {
                        qc.try_cev0_bytes().unwrap()
                    }
                    trnm_consensus_types::ContextAuthorizedQcV0::Epoch(qc) => {
                        qc.try_cev0_bytes().unwrap()
                    }
                },
            };
            assert_eq!(
                runtime
                    .decode_verify_qc_reference_v1(
                        &bytes,
                        &mut Cev0AdmissionBudgetV0::protocol_v0()
                    )
                    .unwrap(),
                *reference
            );
            let mut trailing = bytes;
            trailing.push(0);
            assert!(runtime
                .decode_verify_qc_reference_v1(&trailing, &mut Cev0AdmissionBudgetV0::protocol_v0())
                .is_err());
        }
    }
    assert!(runtime
        .decode_verify_qc_reference_v1(&old_qc, &mut Cev0AdmissionBudgetV0::protocol_v0())
        .is_err());
    assert!(runtime
        .decode_verify_finality_v1(
            &raw,
            parent_time + 1,
            &mut Cev0AdmissionBudgetV0::protocol_v0()
        )
        .is_err());
}

#[test]
fn successor_context_rejects_same_epoch_or_missing_retained_ancestry() {
    use trnm_consensus_crypto::StrictEpochRuntimeContextV1;
    let (evidence, old_set, old_parameters, binding) = fixture("positive");
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_parameters,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let predecessor = StrictEpochRuntimeContextV1::from_activation_v1(activation).unwrap();
    let (same_evidence, same_old_set, same_old_parameters, same_binding) = fixture("positive");
    let same_activation = recover_epoch_activation_authority_strict_v0(
        same_evidence.as_preimages(),
        &same_old_set,
        &same_old_parameters,
        same_binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let successor = StrictEpochRuntimeContextV1::from_activation_v1(same_activation).unwrap();
    let error = StrictEpochRuntimeContextV1::compose_successor_v1(&predecessor, successor, &[])
        .expect_err("a repeated epoch context must never be accepted as a successor");
    assert!(matches!(
        error,
        trnm_consensus_types::ValidationError::InvalidProposal(
            "successor old context differs from predecessor new context"
        )
    ));
}
