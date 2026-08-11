use alloc::vec;

use super::*;
use crate::{
    canonical::{
        try_canonical_bytes, try_canonical_hash, DOMAIN_BLOCK, DOMAIN_CONSUMPTION_CERTIFICATE,
        DOMAIN_CONSUMPTION_CERTIFICATE_ID, DOMAIN_DOUBLE_SIGN_EVIDENCE, DOMAIN_EPOCH_COMMITMENT,
        DOMAIN_FINALITY_PROOF, DOMAIN_HANDOFF_CERTIFICATE, DOMAIN_HANDOFF_DESCRIPTOR,
        DOMAIN_HANDOFF_VOTE, DOMAIN_ORDERED_LEAF, DOMAIN_ORDERED_NODE, DOMAIN_ORDERED_ROOT,
        DOMAIN_PARAMETERS, DOMAIN_PROPOSAL, DOMAIN_QUORUM_CERTIFICATE, DOMAIN_SIGN_INTENT,
        DOMAIN_TIMEOUT, DOMAIN_TIMEOUT_CERTIFICATE, DOMAIN_UPGRADE_PLAN, DOMAIN_VALIDATOR_KEY_POP,
        DOMAIN_VALIDATOR_SET, DOMAIN_VOTE,
    },
    message::proposal_signing_root_from_digests,
};

const CHAIN: ChainId = ChainId::from_static("trnm-test-0");

fn fixed_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let source = value.as_bytes();
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (hex_nibble(source[index * 2]) << 4) | hex_nibble(source[index * 2 + 1]);
    }
    output
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid lowercase hex fixture"),
    }
}

fn pattern(start: u8) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (offset, byte) in output.iter_mut().enumerate() {
        *byte = start + offset as u8;
    }
    output
}

fn signature(index: u8) -> SignatureBytes {
    SignatureBytes::from_array([index; SIGNATURE_BYTES])
}

fn assert_invalid_parameters(mutate: impl FnOnce(&mut ConsensusParametersV0Fields)) {
    let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
    mutate(&mut fields);
    assert!(ConsensusParametersV0::new(fields).is_err());
}

#[test]
fn cev0_primitives_match_wire_foundation_v0() {
    assert_eq!(
        try_canonical_bytes(|encoder| encoder.u8(255)).unwrap(),
        [0xff]
    );
    assert_eq!(
        try_canonical_bytes(|encoder| encoder.u16(0x0102)).unwrap(),
        [0x01, 0x02]
    );
    assert_eq!(
        try_canonical_bytes(|encoder| encoder.u32(0x0102_0304)).unwrap(),
        [0x01, 0x02, 0x03, 0x04]
    );
    assert_eq!(
        try_canonical_bytes(|encoder| encoder.u64(0x0102_0304_0506_0708)).unwrap(),
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    );
    assert_eq!(
        try_canonical_bytes(|encoder| encoder.u128(u128::MAX)).unwrap(),
        [0xff; 16]
    );
    assert_eq!(
        try_canonical_bytes(|encoder| encoder.bool(false)).unwrap(),
        [0]
    );
    assert_eq!(
        try_canonical_bytes(|encoder| encoder.bool(true)).unwrap(),
        [1]
    );
    assert_eq!(
        try_canonical_bytes(|encoder| encoder.bytes(&[0, 1, 2])).unwrap(),
        [0, 0, 0, 3, 0, 1, 2]
    );
    assert_eq!(
        try_canonical_bytes(|encoder| encoder.consensus_string(b"trnm-test-0")).unwrap(),
        [0, 11, b't', b'r', b'n', b'm', b'-', b't', b'e', b's', b't', b'-', b'0']
    );
    assert_eq!(
        try_canonical_bytes(|encoder| {
            encoder.list_len(2);
            encoder.u16(0);
            encoder.u16(258);
        })
        .unwrap(),
        [0, 0, 0, 2, 0, 0, 1, 2]
    );
    assert_eq!(
        try_canonical_bytes(|encoder| encoder.optional(false, |_| {})).unwrap(),
        [0]
    );
    let optional_hash = try_canonical_bytes(|encoder| {
        let hash = pattern(0);
        encoder.optional(true, |encoder| encoder.fixed(&hash));
    })
    .unwrap();
    assert_eq!(optional_hash[0], 1);
    assert_eq!(&optional_hash[1..], &pattern(0));
}

#[test]
fn every_frozen_domain_matches_empty_payload_vector() {
    let vectors = [
        (
            DOMAIN_BLOCK,
            "7ca6f4b4a0fff78a128871b51e66828b3e796fcd137fa50e28dbad04be537423",
        ),
        (
            DOMAIN_PROPOSAL,
            "eb64030be02fc9bb24e3ad21105b12460c4518d0a6de1c7d066c383f99a15627",
        ),
        (
            DOMAIN_VOTE,
            "c6a79bbe9530cc8bcca47c98685961f1cda63c2982563f6b818f2f91b12e8d9b",
        ),
        (
            DOMAIN_TIMEOUT,
            "d8c0749929d468bd016e25f8ac872de594d46969b979ec22b8ab2f4614c79438",
        ),
        (
            DOMAIN_SIGN_INTENT,
            "6ffcdc164b76ed0bde5b33304168003061bb6519feaeebcc9565e318db2ee1e6",
        ),
        (
            DOMAIN_QUORUM_CERTIFICATE,
            "37213a423b7145f565be68e68267e0a5cbc43f9ac03ba73b67d9d4c0a0e47404",
        ),
        (
            DOMAIN_TIMEOUT_CERTIFICATE,
            "b5aa6c6d03062948933f0b34539c3eeb04ec8411bd1bdad765af92ef37e49667",
        ),
        (
            DOMAIN_HANDOFF_DESCRIPTOR,
            "3193e98118a5ad15acd46ac59d083cf88be44735d7ac57d54619d8bb8f297bf7",
        ),
        (
            DOMAIN_HANDOFF_VOTE,
            "fd070fc112f91b4698a7eb76033bc9d46e44b82519aa903680c1fd28abe10bce",
        ),
        (
            DOMAIN_HANDOFF_CERTIFICATE,
            "83284b5d62f96b84ef05e733395e71ad0a10fd85409b74a1e181baf856ffee80",
        ),
        (
            DOMAIN_VALIDATOR_SET,
            "78d9f57c6382d7559bc35712a2936aed68634203c4e2af88a85aed9c9bda3457",
        ),
        (
            DOMAIN_VALIDATOR_KEY_POP,
            "8314bb8f070169d9252a3f215cf24a699dca6111d37632e91373f5d5d329dbe1",
        ),
        (
            DOMAIN_PARAMETERS,
            "2d1b32deb71ff788ff6a50c57f26a49cf61b4467ac9d5618fb0d50e6abb7255a",
        ),
        (
            DOMAIN_EPOCH_COMMITMENT,
            "19a05d8b547f78490aba398b1609b96b165500c1907bf234956fd2335cec5a1a",
        ),
        (
            DOMAIN_UPGRADE_PLAN,
            "897040f964f12d9e1ca3bf24295f649b9c6dcfbd85a5f4a4e8855840f101e0ba",
        ),
        (
            DOMAIN_FINALITY_PROOF,
            "856d798811663446ba2115d3d223c596f7b2776192d392c4172db4fcd6aec6c7",
        ),
        (
            DOMAIN_DOUBLE_SIGN_EVIDENCE,
            "a491a6732951b05369b65f737faa14dc3f24c8909fa652d0c3a9cbdb66cbc8a3",
        ),
        (
            DOMAIN_ORDERED_LEAF,
            "47f6408985f9bd991cb412e8a194bb70c128fcbc43434a9cff23e82ddb8c40be",
        ),
        (
            DOMAIN_ORDERED_NODE,
            "1d3cc7b94cff8c987dc432d1ed5f6f069a39a74bb222e8eebebf51ab7c5d88bf",
        ),
        (
            DOMAIN_ORDERED_ROOT,
            "768c6ab896de3770a4cb671f0bbe8378bfa7157210f672c60f99e5ff966e2139",
        ),
        (
            DOMAIN_CONSUMPTION_CERTIFICATE,
            "66c676b203e64c79ab834c5e8a04fb2f1a624d239a5245889f70c355933b8fc5",
        ),
        (
            DOMAIN_CONSUMPTION_CERTIFICATE_ID,
            "dd698c752db4556b1dcced6f92c3dd8595f86632b709e550e52d9f41db1c94aa",
        ),
    ];
    for (domain, expected) in vectors {
        assert_eq!(
            try_canonical_hash(domain, |_| {}).unwrap(),
            fixed_hex::<32>(expected),
            "domain {}",
            core::str::from_utf8(domain).unwrap()
        );
    }
}

#[test]
fn consensus_parameters_v0_matches_independent_reference_vector() {
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let expected_cev0 = fixed_hex::<341>(
        "000000000000000080008000400000008000000000000400000064000000020000000300000001030fffffffffffffff000000000000ea60000100000000000003e8000000030000000200000000000075300000000000002710020000000000000064010100000000000000020000000100000000000f424000000000000000020000000000000014000000000000c350000000000000000000000000000f42400000000000000000000000000098968000000000000000000000000002faf0800000000000000000000000001dcd6500000000000000000000000000000f42400000000000000000000000003b9aca00000000000000000100000000000f4240000000000003d090000000000003d09000000000000f424000000000000000000a000000000000000a000000000000001400000000000000001c000000000000001e000000000000000200000000000000150101",
    );

    assert_eq!(parameters.canonical_bytes().as_slice(), expected_cev0);
    assert_eq!(
        parameters.hash().into_bytes(),
        fixed_hex("49e6ddaf2ef8e59844b0fd8fc78322019cd04ce3b704466d71c5f7b8d8e0b885")
    );
    parameters.validate_safety_invariants().unwrap();
    parameters.validate_reference_shadow_profile().unwrap();
}

#[test]
fn consensus_parameters_v0_exposes_every_frozen_field() {
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let reconstructed = ConsensusParametersV0Fields {
        schema_version: parameters.schema_version(),
        protocol_version: parameters.protocol_version(),
        production_activation: parameters.production_activation(),
        max_chain_id_bytes: parameters.max_chain_id_bytes(),
        max_validator_id_bytes: parameters.max_validator_id_bytes(),
        max_block_bytes: parameters.max_block_bytes(),
        max_consensus_message_bytes: parameters.max_consensus_message_bytes(),
        min_validators: parameters.min_validators(),
        max_validators: parameters.max_validators(),
        quorum_numerator: parameters.quorum_numerator(),
        quorum_denominator: parameters.quorum_denominator(),
        quorum_addend: parameters.quorum_addend(),
        finality_certified_chain_length: parameters.finality_certified_chain_length(),
        max_total_voting_power: parameters.max_total_voting_power(),
        max_block_time_step_ms: parameters.max_block_time_step_ms(),
        leader_schedule: parameters.leader_schedule(),
        require_full_payload_before_vote: parameters.require_full_payload_before_vote(),
        base_timeout_ms: parameters.base_timeout_ms(),
        timeout_multiplier_numerator: parameters.timeout_multiplier_numerator(),
        timeout_multiplier_denominator: parameters.timeout_multiplier_denominator(),
        timeout_max_ms: parameters.timeout_max_ms(),
        epoch_length_blocks: parameters.epoch_length_blocks(),
        epoch_seal_blocks: parameters.epoch_seal_blocks(),
        snapshot_lead_blocks: parameters.snapshot_lead_blocks(),
        joint_handoff_old_quorum: parameters.joint_handoff_old_quorum(),
        joint_handoff_new_quorum: parameters.joint_handoff_new_quorum(),
        upgrade_notice_epochs: parameters.upgrade_notice_epochs(),
        max_protocol_version_jump: parameters.max_protocol_version_jump(),
        scale_ppm: parameters.scale_ppm(),
        maturity_epochs: parameters.maturity_epochs(),
        max_certificate_age_epochs: parameters.max_certificate_age_epochs(),
        decay_step_ppm_per_epoch: parameters.decay_step_ppm_per_epoch(),
        per_certificate_unit_cap: parameters.per_certificate_unit_cap(),
        per_consumer_provider_epoch_unit_cap: parameters.per_consumer_provider_epoch_unit_cap(),
        per_task_provider_epoch_unit_cap: parameters.per_task_provider_epoch_unit_cap(),
        per_provider_epoch_unit_cap: parameters.per_provider_epoch_unit_cap(),
        units_per_power: parameters.units_per_power(),
        bond_atomic_units_per_power: parameters.bond_atomic_units_per_power(),
        min_validator_power: parameters.min_validator_power(),
        max_validator_power: parameters.max_validator_power(),
        max_validator_share_ppm: parameters.max_validator_share_ppm(),
        capped_weight_alpha_ppm: parameters.capped_weight_alpha_ppm(),
        full_weight_alpha_ppm: parameters.full_weight_alpha_ppm(),
        rollout_phase: parameters.rollout_phase(),
        minimum_shadow_epochs: parameters.minimum_shadow_epochs(),
        minimum_eligibility_only_epochs: parameters.minimum_eligibility_only_epochs(),
        minimum_capped_weight_epochs: parameters.minimum_capped_weight_epochs(),
        automatic_promotion: parameters.automatic_promotion(),
        evidence_window_epochs: parameters.evidence_window_epochs(),
        unbonding_delay_epochs: parameters.unbonding_delay_epochs(),
        jail_duration_epochs: parameters.jail_duration_epochs(),
        trusting_period_epochs: parameters.trusting_period_epochs(),
        require_trusting_period_less_than_evidence: parameters
            .require_trusting_period_less_than_evidence(),
        require_evidence_window_le_unbonding_delay: parameters
            .require_evidence_window_le_unbonding_delay(),
    };

    assert_eq!(reconstructed, parameters.fields());
}

#[test]
fn consensus_parameter_enum_discriminants_are_frozen_and_unknown_values_fail_closed() {
    assert_eq!(u8::from(LeaderSchedule::CanonicalValidatorRoundRobin), 0);
    assert_eq!(
        LeaderSchedule::try_from(0).unwrap(),
        LeaderSchedule::CanonicalValidatorRoundRobin
    );
    assert!(LeaderSchedule::try_from(1).is_err());

    assert_eq!(u8::from(RolloutPhase::Shadow), 0);
    assert_eq!(u8::from(RolloutPhase::EligibilityOnly), 1);
    assert_eq!(u8::from(RolloutPhase::CappedWeight), 2);
    assert_eq!(u8::from(RolloutPhase::Full), 3);
    assert!(RolloutPhase::try_from(4).is_err());
    assert!(RolloutPhase::try_from(u8::MAX).is_err());
}

#[test]
fn governed_activation_is_not_confused_with_the_reference_shadow_profile() {
    let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
    fields.production_activation = true;
    fields.rollout_phase = RolloutPhase::EligibilityOnly;
    let governed = ConsensusParametersV0::new(fields).unwrap();
    governed.validate_safety_invariants().unwrap();
    assert!(governed.validate_reference_shadow_profile().is_err());

    let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
    fields.rollout_phase = RolloutPhase::Full;
    let non_reference = ConsensusParametersV0::new(fields).unwrap();
    assert!(non_reference.validate_reference_shadow_profile().is_err());
}

#[test]
fn consensus_parameter_safety_boundaries_fail_closed() {
    assert_invalid_parameters(|fields| fields.schema_version = 1);
    assert_invalid_parameters(|fields| fields.protocol_version = 1);
    assert_invalid_parameters(|fields| fields.max_chain_id_bytes = 0);
    assert_invalid_parameters(|fields| {
        fields.max_chain_id_bytes = (MAX_CONSENSUS_STRING_BYTES + 1) as u16;
    });
    assert_invalid_parameters(|fields| fields.max_validator_id_bytes = 0);
    assert_invalid_parameters(|fields| {
        fields.max_validator_id_bytes = (MAX_VALIDATOR_ID_BYTES + 1) as u16;
    });
    assert_invalid_parameters(|fields| fields.min_validators = 3);
    assert_invalid_parameters(|fields| fields.max_validators = 3);
    assert_invalid_parameters(|fields| fields.max_validators = 101);
    assert_invalid_parameters(|fields| fields.max_block_bytes = 0);
    assert_invalid_parameters(|fields| fields.max_consensus_message_bytes = 0);
    assert_invalid_parameters(|fields| {
        fields.max_block_bytes = fields.max_consensus_message_bytes + 1;
    });
    assert_invalid_parameters(|fields| fields.quorum_numerator = 3);
    assert_invalid_parameters(|fields| fields.quorum_denominator = 4);
    assert_invalid_parameters(|fields| fields.quorum_addend = 0);
    assert_invalid_parameters(|fields| fields.finality_certified_chain_length = 2);
    assert_invalid_parameters(|fields| fields.require_full_payload_before_vote = false);

    assert_invalid_parameters(|fields| fields.timeout_multiplier_denominator = 0);
    assert_invalid_parameters(|fields| {
        fields.timeout_multiplier_numerator = fields.timeout_multiplier_denominator;
    });
    assert_invalid_parameters(|fields| fields.base_timeout_ms = fields.timeout_max_ms + 1);

    assert_invalid_parameters(|fields| fields.epoch_seal_blocks = 1);
    assert_invalid_parameters(|fields| fields.snapshot_lead_blocks = 0);
    assert_invalid_parameters(|fields| fields.snapshot_lead_blocks = 2);
    assert_invalid_parameters(|fields| fields.snapshot_lead_blocks = u64::MAX);
    assert_invalid_parameters(|fields| {
        fields.epoch_length_blocks =
            fields.snapshot_lead_blocks + u64::from(fields.epoch_seal_blocks);
    });
    assert_invalid_parameters(|fields| fields.joint_handoff_old_quorum = false);
    assert_invalid_parameters(|fields| fields.joint_handoff_new_quorum = false);
    assert_invalid_parameters(|fields| fields.upgrade_notice_epochs = 0);
    assert_invalid_parameters(|fields| fields.max_protocol_version_jump = 2);

    let mut boundary_snapshot_lead = ConsensusParametersV0::reference_shadow_v0().fields();
    boundary_snapshot_lead.snapshot_lead_blocks =
        u64::from(boundary_snapshot_lead.finality_certified_chain_length);
    assert!(ConsensusParametersV0::new(boundary_snapshot_lead).is_ok());

    assert_invalid_parameters(|fields| fields.scale_ppm = 0);
    assert_invalid_parameters(|fields| fields.per_certificate_unit_cap = 0);
    assert_invalid_parameters(|fields| {
        fields.per_consumer_provider_epoch_unit_cap = fields.per_certificate_unit_cap - 1;
    });
    assert_invalid_parameters(|fields| fields.units_per_power = 0);
    assert_invalid_parameters(|fields| fields.bond_atomic_units_per_power = 0);
    assert_invalid_parameters(|fields| fields.min_validator_power = 0);
    assert_invalid_parameters(|fields| {
        fields.min_validator_power = fields.max_validator_power + 1;
    });
    assert_invalid_parameters(|fields| fields.max_validator_share_ppm = 0);
    assert_invalid_parameters(|fields| {
        fields.max_validator_share_ppm = fields.scale_ppm.div_ceil(3);
    });
    let mut non_divisible_scale = ConsensusParametersV0::reference_shadow_v0().fields();
    non_divisible_scale.scale_ppm = 10;
    non_divisible_scale.max_validator_share_ppm = 3;
    non_divisible_scale.capped_weight_alpha_ppm = 2;
    non_divisible_scale.full_weight_alpha_ppm = 10;
    assert!(ConsensusParametersV0::new(non_divisible_scale).is_ok());
    assert_invalid_parameters(|fields| {
        fields.capped_weight_alpha_ppm = fields.scale_ppm + 1;
    });
    assert_invalid_parameters(|fields| fields.full_weight_alpha_ppm = fields.scale_ppm - 1);
    assert_invalid_parameters(|fields| fields.max_total_voting_power = 3);
    assert_invalid_parameters(|fields| fields.automatic_promotion = true);

    assert_invalid_parameters(|fields| {
        fields.trusting_period_epochs = fields.evidence_window_epochs;
    });
    assert_invalid_parameters(|fields| {
        fields.evidence_window_epochs = fields.unbonding_delay_epochs + 1;
    });
    assert_invalid_parameters(|fields| {
        fields.require_trusting_period_less_than_evidence = false;
    });
    assert_invalid_parameters(|fields| {
        fields.require_evidence_window_le_unbonding_delay = false;
    });
}

fn vector_validator_set() -> ValidatorSet {
    ValidatorSet::new(
        GenesisHash::new(pattern(0)),
        CHAIN,
        ProtocolVersion::V0,
        Epoch::new(7),
        ConsensusParametersHash::new(pattern(64)),
        vec![
            Validator::new(
                ValidatorId::from_bytes(b"validator-a").unwrap(),
                ConsensusPublicKey::new([0x11; 32]),
                VotingPower::new(3).unwrap(),
            )
            .unwrap(),
            Validator::new(
                ValidatorId::from_bytes(b"validator-b").unwrap(),
                ConsensusPublicKey::new([0x22; 32]),
                VotingPower::new(2).unwrap(),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn vector_header() -> BlockHeader {
    let mut evidence = pattern(0);
    evidence.reverse();
    BlockHeader::new(
        GenesisHash::new(pattern(0)),
        CHAIN,
        ProtocolVersion::V0,
        Epoch::new(7),
        View::new(42),
        Height::new(99),
        BlockKind::Regular,
        BlockId::new(pattern(96)),
        ValidatorId::from_bytes(b"validator-a").unwrap(),
        ValidatorSetId::new(pattern(32)),
        ConsensusParametersHash::new(pattern(64)),
        PayloadDigest::new(pattern(128)),
        StateRoot::new(pattern(160)),
        ReceiptsRoot::new(pattern(192)),
        EvidenceRoot::new(evidence),
        1_700_000_000_000,
        None,
    )
    .unwrap()
}

#[test]
fn rust_foundation_objects_match_independent_vectors() {
    let expected_block_id =
        fixed_hex("f37dcd9417597c664d041fb1631be705c80faa21f9889dead145744ff73e8885");
    let block_id = vector_header().id();
    assert_eq!(block_id.into_bytes(), expected_block_id);

    let set = vector_validator_set();
    assert_eq!(
        set.id().into_bytes(),
        fixed_hex("3fe4549631bce9e77683cdc7441d4f780bd112d6e8348813b180ddbd83c2e564")
    );

    let vote_context = CommonConsensusContextV0::new(
        GenesisHash::new(pattern(0)),
        CHAIN,
        ProtocolVersion::V0,
        Epoch::new(7),
        ValidatorSetId::new(pattern(32)),
        View::new(42),
        MessageKind::Vote,
    )
    .unwrap();
    assert_eq!(
        Vote::signing_root_for(vote_context, Height::new(99), block_id)
            .unwrap()
            .into_bytes(),
        fixed_hex("90ed745f8bc38310e52eabae5355013914d787087fa5c6ab6e42fd7ae698ded1")
    );

    let qc_digest = CertificateId::new(
        try_canonical_hash(DOMAIN_QUORUM_CERTIFICATE, |encoder| {
            for byte in b"sample-qc-preimage-v0" {
                encoder.u8(*byte);
            }
        })
        .unwrap(),
    );
    assert_eq!(
        qc_digest.into_bytes(),
        fixed_hex("f499b0efbdc44cb4ae5156094e012e90146cf61703805cb06455c2c6f5602370")
    );

    let timeout_context = CommonConsensusContextV0::new(
        GenesisHash::new(pattern(0)),
        CHAIN,
        ProtocolVersion::V0,
        Epoch::new(7),
        ValidatorSetId::new(pattern(32)),
        View::new(42),
        MessageKind::Timeout,
    )
    .unwrap();
    let high_qc = QcRef::new(
        qc_digest,
        Epoch::new(7),
        View::new(41),
        Height::new(98),
        BlockId::new(pattern(96)),
        ValidatorSetId::new(pattern(32)),
    );
    assert_eq!(
        TimeoutVote::signing_root_for(timeout_context, high_qc)
            .unwrap()
            .into_bytes(),
        fixed_hex("f6fb855b30a696ae204d480b09a4af38800a2b2d74a94c2ed73a6e65c5773f08")
    );

    let proposal_context = CommonConsensusContextV0::new(
        GenesisHash::new(pattern(0)),
        CHAIN,
        ProtocolVersion::V0,
        Epoch::new(7),
        ValidatorSetId::new(pattern(32)),
        View::new(42),
        MessageKind::Proposal,
    )
    .unwrap();
    assert_eq!(
        proposal_signing_root_from_digests(
            proposal_context,
            Height::new(99),
            block_id,
            qc_digest,
            None,
            None,
        )
        .into_bytes(),
        fixed_hex("4c43933da64bb71ebbee269852b28f3ef95a6e0e4fba26a6d11e90695f334d68")
    );
}

#[test]
fn canonical_sign_intent_binds_preimage_author_and_safety_revision() {
    let set = vector_validator_set();
    let author = ValidatorId::from_bytes(b"validator-a").unwrap();
    let block_id = vector_header().id();
    let vote =
        CanonicalSignIntentV0::vote(&set, author, 17, View::new(42), Height::new(99), block_id)
            .unwrap();

    vote.validate(&set).unwrap();
    assert_eq!(
        vote.schema_version(),
        CANONICAL_SIGN_INTENT_SCHEMA_VERSION_V0
    );
    assert_eq!(vote.chain_id(), set.chain_id());
    assert_eq!(vote.protocol_version(), set.protocol_version());
    assert_eq!(vote.epoch(), set.epoch());
    assert_eq!(vote.validator_set_id(), set.id());
    assert_eq!(vote.author(), author);
    assert_eq!(vote.authorizing_safety_revision(), 17);
    assert_eq!(
        vote.signing_root(),
        Vote::signing_root_for_set(&set, View::new(42), Height::new(99), block_id).unwrap()
    );
    assert_eq!(
        vote.signing_root().into_bytes(),
        fixed_hex("73d3a516141972fe483e56e7d31818dac92bba58aa0ba52d3c894bc4c62b4873")
    );
    assert_eq!(
        vote.fingerprint().into_bytes(),
        fixed_hex("8345d9ce557b38346107fd70b392c487161b9d2d898fc0e605027678ffdb52e7")
    );
    assert_eq!(vote.canonical_bytes().unwrap().len(), 287);
    let vote_golden = fixed_hex::<287>(
        "0000000b74726e6d2d746573742d300000000000000000000000073fe4549631bce9e77683cdc7441d4f780bd112d6e8348813b180ddbd83c2e5640000000b76616c696461746f722d610000000000000011000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000b74726e6d2d746573742d300000000000000000000000073fe4549631bce9e77683cdc7441d4f780bd112d6e8348813b180ddbd83c2e564000000000000002a010000000000000063f37dcd9417597c664d041fb1631be705c80faa21f9889dead145744ff73e888573d3a516141972fe483e56e7d31818dac92bba58aa0ba52d3c894bc4c62b48738345d9ce557b38346107fd70b392c487161b9d2d898fc0e605027678ffdb52e7",
    );
    assert_eq!(vote.canonical_bytes().unwrap(), vote_golden);
    assert_eq!(
        decode_canonical_sign_intent_v0_exact(&vote_golden, &set).unwrap(),
        vote
    );
    assert!(!vote.preimage().canonical_bytes().unwrap().is_empty());
    assert!(
        vote.canonical_bytes().unwrap().len() > vote.preimage().canonical_bytes().unwrap().len()
    );

    let next_revision =
        CanonicalSignIntentV0::vote(&set, author, 18, View::new(42), Height::new(99), block_id)
            .unwrap();
    assert_eq!(next_revision.signing_root(), vote.signing_root());
    assert_ne!(next_revision.fingerprint(), vote.fingerprint());

    assert!(
        CanonicalSignIntentV0::vote(&set, author, 0, View::new(42), Height::new(99), block_id,)
            .is_err()
    );

    let high_qc = QcRef::new(
        CertificateId::new(fixed_hex(
            "f499b0efbdc44cb4ae5156094e012e90146cf61703805cb06455c2c6f5602370",
        )),
        set.epoch(),
        View::new(41),
        Height::new(98),
        BlockId::new(pattern(96)),
        set.id(),
    );
    let timeout =
        CanonicalSignIntentV0::timeout_vote(&set, author, 19, View::new(42), high_qc).unwrap();
    timeout.validate(&set).unwrap();
    assert_eq!(
        timeout.signing_root(),
        TimeoutVote::signing_root_for_set(&set, View::new(42), high_qc).unwrap()
    );
    assert_eq!(
        timeout.signing_root().into_bytes(),
        fixed_hex("c182b0cb4b34881ae7929b7f365d9117d0eedb8be8faa996a8afef7d70fb0efa")
    );
    assert_eq!(
        timeout.fingerprint().into_bytes(),
        fixed_hex("d9436f0d29a8ea20b98dc0c80a51ae2d0fa00c31a39a0692d1defd12d5aab96a")
    );
    assert_eq!(timeout.canonical_bytes().unwrap().len(), 335);
    let timeout_golden = fixed_hex::<335>(
        "0000000b74726e6d2d746573742d300000000000000000000000073fe4549631bce9e77683cdc7441d4f780bd112d6e8348813b180ddbd83c2e5640000000b76616c696461746f722d610000000000000013010000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000b74726e6d2d746573742d300000000000000000000000073fe4549631bce9e77683cdc7441d4f780bd112d6e8348813b180ddbd83c2e564000000000000002a02f499b0efbdc44cb4ae5156094e012e90146cf61703805cb06455c2c6f5602370000000000000000700000000000000290000000000000062606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7fc182b0cb4b34881ae7929b7f365d9117d0eedb8be8faa996a8afef7d70fb0efad9436f0d29a8ea20b98dc0c80a51ae2d0fa00c31a39a0692d1defd12d5aab96a",
    );
    assert_eq!(timeout.canonical_bytes().unwrap(), timeout_golden);
    assert_eq!(
        decode_canonical_sign_intent_v0_exact(&timeout_golden, &set).unwrap(),
        timeout
    );
    assert_ne!(timeout.fingerprint(), vote.fingerprint());
}

#[test]
fn canonical_sign_intent_decoder_is_bounded_exact_and_fail_closed() {
    let set = vector_validator_set();
    let author = ValidatorId::from_bytes(b"validator-a").unwrap();
    let intent = CanonicalSignIntentV0::vote(
        &set,
        author,
        17,
        View::new(42),
        Height::new(99),
        vector_header().id(),
    )
    .unwrap();
    let canonical = intent.canonical_bytes().unwrap();
    assert_eq!(
        decode_canonical_sign_intent_v0_exact(&canonical, &set).unwrap(),
        intent
    );

    let chain_length = set.chain_id().as_bytes().len();
    let author_length = author.as_bytes().len();
    let outer_protocol_offset = 2 + 2 + chain_length;
    let outer_set_offset = outer_protocol_offset + 4 + 8;
    let author_length_offset = outer_set_offset + 32;
    let revision_offset = author_length_offset + 4 + author_length;
    let tag_offset = revision_offset + 8;
    let context_offset = tag_offset + 1;
    let context_kind_offset = context_offset + 2 + 32 + 2 + chain_length + 4 + 8 + 32 + 8;
    let signing_root_offset = canonical.len() - 64;
    let fingerprint_offset = canonical.len() - 32;
    assert_eq!(
        (
            outer_protocol_offset,
            outer_set_offset,
            revision_offset,
            tag_offset
        ),
        (15, 27, 74, 82)
    );

    let assert_code = |bytes: &[u8], expected: DecodeErrorCode| {
        let error = decode_canonical_sign_intent_v0_exact(bytes, &set).unwrap_err();
        assert_eq!(error.code(), expected);
        error
    };

    let mut tampered = canonical.clone();
    tampered[1] = 1;
    assert_code(&tampered, DecodeErrorCode::InvalidSchemaVersion);

    let mut tampered = canonical.clone();
    tampered[2..4].copy_from_slice(&129u16.to_be_bytes());
    assert_code(&tampered, DecodeErrorCode::LengthLimitExceeded);

    let mut tampered = canonical.clone();
    tampered[author_length_offset..author_length_offset + 4].copy_from_slice(&129u32.to_be_bytes());
    assert_code(&tampered, DecodeErrorCode::LengthLimitExceeded);

    let mut tampered = canonical.clone();
    tampered[outer_protocol_offset + 3] = 1;
    assert_code(&tampered, DecodeErrorCode::InvalidProtocolVersion);

    let mut tampered = canonical.clone();
    tampered[outer_set_offset] ^= 1;
    assert_code(&tampered, DecodeErrorCode::ContextMismatch);

    let mut tampered = canonical.clone();
    tampered[revision_offset..revision_offset + 8].fill(0);
    let error = assert_code(&tampered, DecodeErrorCode::InvalidSignIntent);
    assert_eq!(error.byte_offset(), revision_offset);

    let mut tampered = canonical.clone();
    tampered[revision_offset + 7] ^= 1;
    let error = assert_code(&tampered, DecodeErrorCode::InvalidSignIntent);
    assert_eq!(error.byte_offset(), fingerprint_offset);

    let mut tampered = canonical.clone();
    tampered[tag_offset] = 2;
    let error = assert_code(&tampered, DecodeErrorCode::InvalidSignIntentTag);
    assert_eq!(error.byte_offset(), tag_offset);

    let mut tampered = canonical.clone();
    tampered[context_offset + 2] ^= 1;
    assert_code(&tampered, DecodeErrorCode::ContextMismatch);

    let mut tampered = canonical.clone();
    tampered[context_kind_offset] = MessageKind::Timeout as u8;
    assert_code(&tampered, DecodeErrorCode::ContextMismatch);

    let mut tampered = canonical.clone();
    tampered[signing_root_offset] ^= 1;
    let error = assert_code(&tampered, DecodeErrorCode::InvalidSignIntent);
    assert_eq!(error.byte_offset(), signing_root_offset);

    let mut tampered = canonical.clone();
    tampered[fingerprint_offset] ^= 1;
    let error = assert_code(&tampered, DecodeErrorCode::InvalidSignIntent);
    assert_eq!(error.byte_offset(), fingerprint_offset);

    let mut truncated = canonical.clone();
    truncated.pop();
    assert_code(&truncated, DecodeErrorCode::UnexpectedEof);

    let mut trailing = canonical.clone();
    trailing.push(0);
    let error = assert_code(&trailing, DecodeErrorCode::TrailingBytes);
    assert_eq!(error.byte_offset(), canonical.len());

    let oversized = vec![0; MAX_CEV0_CANONICAL_SIGN_INTENT_BYTES + 1];
    let error = assert_code(&oversized, DecodeErrorCode::LengthLimitExceeded);
    assert_eq!(error.byte_offset(), 0);
}

#[test]
fn consensus_strings_validator_ids_and_signatures_are_fail_closed() {
    assert_eq!(ChainId::new("trnm-test-0").unwrap(), CHAIN);
    assert!(ChainId::new("TRNM").is_err());
    assert!(ChainId::new("").is_err());
    assert!(ValidatorId::from_bytes(&[]).is_err());
    assert!(ValidatorId::from_bytes(&[1; MAX_VALIDATOR_ID_BYTES + 1]).is_err());
    assert!(
        ValidatorId::from_bytes(&[1, 0]).unwrap() < ValidatorId::from_bytes(&[0xff]).unwrap(),
        "validator IDs must use raw-byte lexicographic order, not length-first order"
    );
    assert!(SignatureBytes::new(vec![1; 63]).is_err());
    assert!(SignatureBytes::new(vec![1; 65]).is_err());
    assert_eq!(signature(1).as_bytes().len(), 64);
}

#[test]
fn validator_set_rejects_noncanonical_ids_duplicates_and_duplicate_keys() {
    let set = unit_set();
    let reversed = ValidatorSet::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        set.consensus_parameters_hash(),
        vec![unit_validator(2), unit_validator(1)],
    );
    assert_eq!(reversed, Err(ValidationError::NonCanonicalValidatorOrder));

    let duplicate_id = ValidatorSet::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        set.consensus_parameters_hash(),
        vec![unit_validator(1), unit_validator(1)],
    );
    assert!(matches!(
        duplicate_id,
        Err(ValidationError::DuplicateValidatorId(id)) if *id == unit_validator_id(1)
    ));

    let duplicate_key = Validator::new(
        unit_validator_id(2),
        unit_validator(1).consensus_key(),
        VotingPower::new(1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        ValidatorSet::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            set.consensus_parameters_hash(),
            vec![unit_validator(1), duplicate_key],
        ),
        Err(ValidationError::DuplicateConsensusPublicKey)
    );
}

#[test]
fn validator_set_parameter_bounds_are_consensus_rules() {
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let make_validator = |index: u8, power: u64| {
        Validator::new(
            unit_validator_id(index),
            ConsensusPublicKey::new([index + 100; 32]),
            VotingPower::new(power).unwrap(),
        )
        .unwrap()
    };
    let make_set = |validators| {
        ValidatorSet::new(
            GenesisHash::new([1; 32]),
            ChainId::from_static("trnm-parameter-set-0"),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap()
    };

    let valid = make_set(vec![
        make_validator(1, 1),
        make_validator(2, 1),
        make_validator(3, 1),
        make_validator(4, 1),
    ]);
    valid.validate_against_parameters(&parameters).unwrap();

    let too_small = make_set(vec![make_validator(1, 1)]);
    assert!(matches!(
        too_small.validate_against_parameters(&parameters),
        Err(ValidationError::InvalidValidatorSet(_))
    ));

    let concentrated = make_set(vec![
        make_validator(1, 2),
        make_validator(2, 1),
        make_validator(3, 1),
        make_validator(4, 1),
    ]);
    assert!(matches!(
        concentrated.validate_against_parameters(&parameters),
        Err(ValidationError::InvalidValidatorSet(_))
    ));

    let mut fields = parameters.fields();
    fields.max_chain_id_bytes = 4;
    let narrow_chain_id = ConsensusParametersV0::new(fields).unwrap();
    let long_chain_set = ValidatorSet::new(
        GenesisHash::new([1; 32]),
        ChainId::from_static("trnm-long-0"),
        ProtocolVersion::V0,
        Epoch::new(0),
        narrow_chain_id.hash(),
        vec![
            make_validator(1, 1),
            make_validator(2, 1),
            make_validator(3, 1),
            make_validator(4, 1),
        ],
    )
    .unwrap();
    assert!(matches!(
        long_chain_set.validate_against_parameters(&narrow_chain_id),
        Err(ValidationError::InvalidValidatorSet(_))
    ));

    let mut fields = parameters.fields();
    fields.max_validator_id_bytes = 1;
    let narrow_validator_id = ConsensusParametersV0::new(fields).unwrap();
    let long_id_validator = |index: u8| {
        Validator::new(
            ValidatorId::from_bytes(&[index, 0]).unwrap(),
            ConsensusPublicKey::new([index + 100; 32]),
            VotingPower::new(1).unwrap(),
        )
        .unwrap()
    };
    let long_id_set = ValidatorSet::new(
        GenesisHash::new([1; 32]),
        ChainId::from_static("trnm-id-0"),
        ProtocolVersion::V0,
        Epoch::new(0),
        narrow_validator_id.hash(),
        vec![
            long_id_validator(1),
            long_id_validator(2),
            long_id_validator(3),
            long_id_validator(4),
        ],
    )
    .unwrap();
    assert!(matches!(
        long_id_set.validate_against_parameters(&narrow_validator_id),
        Err(ValidationError::InvalidValidatorSet(_))
    ));
}

fn unit_validator_id(index: u8) -> ValidatorId {
    ValidatorId::from_bytes(&[index]).unwrap()
}

fn unit_validator(index: u8) -> Validator {
    Validator::new(
        unit_validator_id(index),
        ConsensusPublicKey::new([index + 100; 32]),
        VotingPower::new(1).unwrap(),
    )
    .unwrap()
}

fn unit_set() -> ValidatorSet {
    ValidatorSet::new(
        GenesisHash::new([1; 32]),
        ChainId::from_static("trnm-unit-0"),
        ProtocolVersion::V0,
        Epoch::new(0),
        ConsensusParametersHash::new([2; 32]),
        vec![
            unit_validator(1),
            unit_validator(2),
            unit_validator(3),
            unit_validator(4),
        ],
    )
    .unwrap()
}

fn unit_header(set: &ValidatorSet, view: u64, height: u64, parent: BlockId) -> BlockHeader {
    BlockHeader::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        BlockKind::Regular,
        parent,
        unit_validator_id(1),
        set.id(),
        set.consensus_parameters_hash(),
        PayloadDigest::new([height as u8; 32]),
        StateRoot::new([height as u8; 32]),
        ReceiptsRoot::new([height as u8; 32]),
        EvidenceRoot::new([height as u8; 32]),
        height,
        None,
    )
    .unwrap()
}

fn unit_vote(set: &ValidatorSet, header: &BlockHeader, author: u8) -> Vote {
    Vote::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        header.view(),
        header.height(),
        header.id(),
        set.id(),
        unit_validator_id(author),
        signature(author),
        set,
    )
    .unwrap()
}

fn unit_qc(set: &ValidatorSet, header: &BlockHeader) -> QuorumCertificate {
    QuorumCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        header.view(),
        header.height(),
        header.id(),
        set.id(),
        vec![
            unit_vote(set, header, 1),
            unit_vote(set, header, 2),
            unit_vote(set, header, 3),
        ],
        set,
    )
    .unwrap()
}

fn unit_qc_for_coordinates(
    set: &ValidatorSet,
    view: u64,
    height: u64,
    block_id: BlockId,
) -> QuorumCertificate {
    let votes = (1..=3)
        .map(|author| {
            Vote::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(view),
                Height::new(height),
                block_id,
                set.id(),
                unit_validator_id(author),
                signature(author),
                set,
            )
            .unwrap()
        })
        .collect();
    QuorumCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(view),
        Height::new(height),
        block_id,
        set.id(),
        votes,
        set,
    )
    .unwrap()
}

fn unit_timeout_vote(
    set: &ValidatorSet,
    timeout_view: u64,
    high_qc: QcRef,
    author: u8,
) -> TimeoutVote {
    TimeoutVote::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(timeout_view),
        set.id(),
        high_qc,
        unit_validator_id(author),
        signature(author),
        set,
    )
    .unwrap()
}

#[test]
fn qc_rejects_insufficient_weight_and_noncanonical_signer_order() {
    let set = unit_set();
    let header = unit_header(&set, 1, 1, BlockId::new([9; 32]));
    let insufficient = QuorumCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        header.view(),
        header.height(),
        header.id(),
        set.id(),
        vec![unit_vote(&set, &header, 1), unit_vote(&set, &header, 2)],
        &set,
    );
    assert!(matches!(
        insufficient,
        Err(ValidationError::InsufficientQuorum {
            signed: 2,
            required: 3
        })
    ));

    let noncanonical = QuorumCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        header.view(),
        header.height(),
        header.id(),
        set.id(),
        vec![
            unit_vote(&set, &header, 2),
            unit_vote(&set, &header, 1),
            unit_vote(&set, &header, 3),
        ],
        &set,
    );
    assert_eq!(noncanonical, Err(ValidationError::NonCanonicalSignerOrder));

    let view_zero_block = BlockId::new([7; 32]);
    let view_zero_votes = (1..=3)
        .map(|author| {
            Vote::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(0),
                Height::new(0),
                view_zero_block,
                set.id(),
                unit_validator_id(author),
                signature(author),
                &set,
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(0),
            Height::new(0),
            view_zero_block,
            set.id(),
            view_zero_votes,
            &set,
        ),
        Err(ValidationError::InvalidCertificate(
            "ordinary QC view must be positive"
        ))
    );
}

#[test]
fn qc_and_tc_recompute_weight_and_bind_exact_referenced_qc() {
    let set = unit_set();
    assert_eq!(set.total_power(), 4);
    assert_eq!(set.quorum_power(), 3);
    let header = unit_header(&set, 1, 1, BlockId::new([9; 32]));
    let high_qc = unit_qc(&set, &header);
    let high_qc_ref = QcRef::from(&high_qc);
    let timeout_votes = (1..=3)
        .map(|author| {
            TimeoutVote::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(2),
                set.id(),
                high_qc_ref,
                unit_validator_id(author),
                signature(author),
                &set,
            )
            .unwrap()
        })
        .collect();
    let tc = TimeoutCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(2),
        set.id(),
        high_qc.clone(),
        timeout_votes,
        &set,
    )
    .unwrap();
    assert_eq!(tc.high_qc().id(), high_qc.id());
    assert_eq!(tc.referenced_qcs().len(), 1);

    let fake_ref = QcRef::new(
        CertificateId::new([0xee; 32]),
        high_qc_ref.epoch(),
        high_qc_ref.view(),
        high_qc_ref.height(),
        high_qc_ref.block_id(),
        high_qc_ref.validator_set_id(),
    );
    let fake_timeout_votes = (1..=3)
        .map(|author| {
            TimeoutVote::new(
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(2),
                set.id(),
                fake_ref,
                unit_validator_id(author),
                signature(author),
                &set,
            )
            .unwrap()
        })
        .collect();
    assert!(matches!(
        TimeoutCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(2),
            set.id(),
            high_qc,
            fake_timeout_votes,
            &set,
        ),
        Err(ValidationError::InvalidCertificate(
            "timeout entry references an absent QC"
        ))
    ));
}

#[test]
fn tc_multiple_referenced_qcs_enforce_digest_order_exact_entries_and_maximum() {
    let set = unit_set();
    let first_header = unit_header(&set, 1, 1, BlockId::new([9; 32]));
    let first_qc = unit_qc(&set, &first_header);
    let second_header = unit_header(&set, 2, 2, first_header.id());
    let second_qc = unit_qc(&set, &second_header);
    let entries = vec![
        unit_timeout_vote(&set, 3, QcRef::from(&first_qc), 1),
        unit_timeout_vote(&set, 3, QcRef::from(&second_qc), 2),
        unit_timeout_vote(&set, 3, QcRef::from(&second_qc), 3),
    ];
    let mut referenced = vec![first_qc.clone(), second_qc.clone()];
    referenced.sort_by_key(QuorumCertificate::id);
    let tc = TimeoutCertificate::new_with_referenced_qcs(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(3),
        set.id(),
        referenced.clone(),
        second_qc.id(),
        entries.clone(),
        &set,
    )
    .unwrap();
    assert_eq!(tc.high_qc().id(), second_qc.id());
    assert_eq!(tc.referenced_qcs().len(), 2);

    let mut reversed = referenced.clone();
    reversed.reverse();
    assert_eq!(
        TimeoutCertificate::new_with_referenced_qcs(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(3),
            set.id(),
            reversed,
            second_qc.id(),
            entries.clone(),
            &set,
        ),
        Err(ValidationError::NonCanonicalQcOrder)
    );
    assert!(matches!(
        TimeoutCertificate::new_with_referenced_qcs(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(3),
            set.id(),
            referenced.clone(),
            first_qc.id(),
            entries,
            &set,
        ),
        Err(ValidationError::InvalidCertificate(
            "TC selected high QC is not the deterministic maximum"
        ))
    ));

    let mismatched_summary = QcRef::new(
        first_qc.id(),
        second_qc.epoch(),
        second_qc.view(),
        second_qc.height(),
        second_qc.block_id(),
        second_qc.validator_set_id(),
    );
    let mismatched_entries = vec![
        unit_timeout_vote(&set, 3, mismatched_summary, 1),
        unit_timeout_vote(&set, 3, QcRef::from(&second_qc), 2),
        unit_timeout_vote(&set, 3, QcRef::from(&second_qc), 3),
    ];
    assert_eq!(
        TimeoutCertificate::new_with_referenced_qcs(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(3),
            set.id(),
            referenced,
            second_qc.id(),
            mismatched_entries,
            &set,
        ),
        Err(ValidationError::CertificateMismatch)
    );
}

#[test]
fn tc_rejects_conflicting_same_view_qcs() {
    let set = unit_set();
    let left = unit_header(&set, 1, 1, BlockId::new([0x10; 32]));
    let right = unit_header(&set, 1, 1, BlockId::new([0x20; 32]));
    let left_qc = unit_qc(&set, &left);
    let right_qc = unit_qc(&set, &right);
    let entries = vec![
        unit_timeout_vote(&set, 2, QcRef::from(&left_qc), 1),
        unit_timeout_vote(&set, 2, QcRef::from(&right_qc), 2),
        unit_timeout_vote(&set, 2, QcRef::from(&right_qc), 3),
    ];
    let selected = if left_qc.block_id() > right_qc.block_id() {
        left_qc.id()
    } else {
        right_qc.id()
    };
    let mut referenced = vec![left_qc, right_qc];
    referenced.sort_by_key(QuorumCertificate::id);
    assert_eq!(
        TimeoutCertificate::new_with_referenced_qcs(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(2),
            set.id(),
            referenced,
            selected,
            entries,
            &set,
        ),
        Err(ValidationError::ConflictingSameViewQc)
    );
}

#[test]
fn tc_allows_same_block_qc_variants_and_tiebreaks_by_qc_digest() {
    let set = unit_set();
    let header = unit_header(&set, 1, 1, BlockId::new([0x10; 32]));
    let first_qc = unit_qc(&set, &header);
    let second_qc = QuorumCertificate::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        header.view(),
        header.height(),
        header.id(),
        set.id(),
        vec![
            unit_vote(&set, &header, 1),
            unit_vote(&set, &header, 2),
            unit_vote(&set, &header, 4),
        ],
        &set,
    )
    .unwrap();
    assert_ne!(first_qc.id(), second_qc.id());

    let entries = vec![
        unit_timeout_vote(&set, 2, QcRef::from(&first_qc), 1),
        unit_timeout_vote(&set, 2, QcRef::from(&second_qc), 2),
        unit_timeout_vote(&set, 2, QcRef::from(&second_qc), 3),
    ];
    let selected = core::cmp::max(first_qc.id(), second_qc.id());
    let non_selected = core::cmp::min(first_qc.id(), second_qc.id());
    let mut referenced = vec![first_qc, second_qc];
    referenced.sort_by_key(QuorumCertificate::id);

    let tc = TimeoutCertificate::new_with_referenced_qcs(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(2),
        set.id(),
        referenced.clone(),
        selected,
        entries.clone(),
        &set,
    )
    .unwrap();
    assert_eq!(tc.high_qc().id(), selected);

    assert!(matches!(
        TimeoutCertificate::new_with_referenced_qcs(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(2),
            set.id(),
            referenced,
            non_selected,
            entries,
            &set,
        ),
        Err(ValidationError::InvalidCertificate(
            "TC selected high QC is not the deterministic maximum"
        ))
    ));
}

#[test]
fn timeout_certificate_v0_rejects_a_block_id_reused_at_other_coordinates() {
    let set = unit_set();
    let block_id = BlockId::new([0x42; 32]);

    for second_height in [1, 2] {
        let first = unit_qc_for_coordinates(&set, 1, 1, block_id);
        let second = unit_qc_for_coordinates(&set, 2, second_height, block_id);
        let first_ref = QcRef::from(&first);
        let second_ref = QcRef::from(&second);
        let entries = vec![
            TimeoutEntryV0::new(unit_validator_id(1), first_ref, signature(1)).unwrap(),
            TimeoutEntryV0::new(unit_validator_id(2), second_ref, signature(2)).unwrap(),
            TimeoutEntryV0::new(unit_validator_id(3), second_ref, signature(3)).unwrap(),
        ];
        let mut referenced = vec![
            QcReferenceV0::ordinary(first),
            QcReferenceV0::ordinary(second.clone()),
        ];
        referenced.sort_by_key(QcReferenceV0::id);

        assert!(matches!(
            TimeoutCertificateV0::new(View::new(3), entries, referenced, second.id(), &set,),
            Err(ValidationError::InvalidCertificate(
                "TC binds one block ID to multiple QC coordinates"
            ))
        ));
    }
}

#[test]
fn equivocation_evidence_requires_two_conflicting_signed_votes() {
    let set = unit_set();
    let first = Vote::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(5),
        Height::new(9),
        BlockId::new([1; 32]),
        set.id(),
        unit_validator_id(1),
        signature(1),
        &set,
    )
    .unwrap();
    let second = Vote::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(5),
        Height::new(9),
        BlockId::new([2; 32]),
        set.id(),
        unit_validator_id(1),
        signature(2),
        &set,
    )
    .unwrap();
    let evidence = EquivocationEvidence::vote(first.clone(), second, &set).unwrap();
    assert_eq!(evidence.offender(), unit_validator_id(1));
    assert!(EquivocationEvidence::vote(first.clone(), first.clone(), &set).is_err());

    let same_block_different_height = Vote::new(
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        View::new(5),
        Height::new(10),
        BlockId::new([1; 32]),
        set.id(),
        unit_validator_id(1),
        signature(3),
        &set,
    )
    .unwrap();
    assert!(EquivocationEvidence::vote(first.clone(), same_block_different_height, &set).is_ok());
}

#[test]
fn commit_proof_checks_direct_parent_height_view_and_qc_binding() {
    let set = unit_set();
    let committed = unit_header(&set, 1, 4, BlockId::new([9; 32]));
    let child = unit_header(&set, 2, 5, committed.id());
    let grandchild = unit_header(&set, 3, 6, child.id());
    let proof = CommitProof::new(
        committed.clone(),
        child.clone(),
        grandchild.clone(),
        unit_qc(&set, &committed),
        unit_qc(&set, &child),
        unit_qc(&set, &grandchild),
        &set,
    )
    .unwrap();
    assert_eq!(proof.committed().id(), committed.id());

    let wrong_grandchild = unit_header(&set, 3, 6, BlockId::new([0xaa; 32]));
    assert!(CommitProof::new(
        committed.clone(),
        child.clone(),
        wrong_grandchild.clone(),
        unit_qc(&set, &committed),
        unit_qc(&set, &child),
        unit_qc(&set, &wrong_grandchild),
        &set,
    )
    .is_err());
}

struct AcceptAllSignatures;

impl SignatureVerifier for AcceptAllSignatures {
    fn verify(
        &self,
        _validator: &Validator,
        _signing_root: &SigningRoot,
        _signature: &SignatureBytes,
    ) -> bool {
        true
    }
}

#[test]
fn cryptography_remains_an_explicit_pure_verifier_boundary() {
    let set = unit_set();
    let header = unit_header(&set, 1, 1, BlockId::new([9; 32]));
    unit_qc(&set, &header)
        .verify(&set, &AcceptAllSignatures)
        .unwrap();
}
