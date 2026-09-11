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
