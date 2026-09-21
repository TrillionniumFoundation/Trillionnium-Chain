use super::*;
use crate::{
    epoch_state_tests_v1, prepare_epoch_handoff_evidence_v2, Core, EpochPreparationEntryV2,
    EpochPreparationV2,
};
use trnm_consensus_crypto::{
    recover_successor_epoch_activation_authority_strict_v1, StrictEpochRuntimeContextV1,
};
use trnm_consensus_types::{Cev0AdmissionBudgetV0, EpochActivationEvidencePreimagesV0};

use crate::epoch_successor_fixture_tests_v2 as successor_fixture;

fn roots<'a>(r: &'a [Vec<u8>; 8]) -> EpochActivationEvidencePreimagesV0<'a> {
    EpochActivationEvidencePreimagesV0 {
        old_checkpoint_finality: &r[0],
        next_epoch_commitment: &r[1],
        authorization_kernel: &r[2],
        old_validator_set: &r[3],
        old_consensus_parameters: &r[4],
        new_validator_set: &r[5],
        new_consensus_parameters: &r[6],
        authenticated_checkpoint_parent_header: &r[7],
    }
}

fn build_preparation() -> (
    EpochPreparationV2,
    CoreConfig,
    ValidatedPayloadArtifactRefV0,
) {
    let predecessor = successor_fixture::predecessor();
    let predecessor_context = StrictEpochRuntimeContextV1::from_activation_v1(predecessor).unwrap();
    let facts = successor_fixture::genuine_successor_fixture_v1(&predecessor_context, true);
    let ancestry_bytes: Vec<Vec<u8>> = facts
        .canonical_ancestry
        .iter()
        .map(|h| h.try_cev0_bytes().unwrap())
        .collect();
    let ancestry: Vec<&[u8]> = ancestry_bytes.iter().map(Vec::as_slice).collect();
    let entries = [
        EpochPreparationEntryV2 {
            binding_ref: facts.root_binding,
            retained_ancestry: &[],
            evidence: roots(&facts.original_roots),
        },
        EpochPreparationEntryV2 {
            binding_ref: facts.terminal_binding,
            retained_ancestry: &ancestry,
            evidence: roots(&facts.second_roots),
        },
    ];
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    let prepared = prepare_epoch_handoff_evidence_v2(
        &entries,
        &facts.root_validator_set,
        &facts.root_parameters,
        facts.root_binding,
        facts.terminal_binding,
        &mut budget,
    )
    .unwrap();
    let terminal = recover_successor_epoch_activation_authority_strict_v1(
        predecessor_context.activation(),
        &facts.canonical_ancestry,
        roots(&facts.second_roots),
        facts.terminal_binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let terminal_runtime = StrictEpochRuntimeContextV1::from_activation_v1(terminal).unwrap();
    let config = epoch_state_tests_v1::config(&terminal_runtime);
    let artifact = epoch_state_tests_v1::artifact(&terminal_runtime);
    (prepared, config, artifact)
}

#[test]
fn codec2_roundtrip_retains_genuine_mixed_anchor_provenance() {
    let (preparation, config, artifact) = build_preparation();
    let limits = minimum_epoch_safety_record_limits_v2(&config, &preparation).unwrap();
    let too_small = SafetyStateRecordLimitsV0::new(
        limits.maximum_record_bytes().saturating_sub(1),
        limits.maximum_blob_bytes(),
    )
    .unwrap();
    assert!(
        EpochSafetyStateRecordContextV2::new(&config, preparation, artifact, 40, too_small,)
            .is_err()
    );
    let (preparation, config, artifact) = build_preparation();
    let original_record = preparation.record_v2().encode_v2().unwrap();
    let limits = minimum_epoch_safety_record_limits_v2(&config, &preparation).unwrap();
    let context =
        EpochSafetyStateRecordContextV2::new(&config, preparation, artifact, 41, limits).unwrap();
    assert_eq!(
        context
            .epoch()
            .preparation_record_v2()
            .unwrap()
            .as_bytes_v2(),
        original_record
    );
    let state =
        SafetyState::from_epoch_activation_v1(&config, context.epoch().clone(), 41).unwrap();
    let raw = encode_epoch_safety_record_v2(&state, &context).unwrap();
    assert!(raw
        .windows(original_record.len())
        .any(|frame| frame == original_record));
    assert_eq!(&raw[..8], b"TRNMS14E");
    assert_eq!(u16::from_be_bytes(raw[8..10].try_into().unwrap()), 2);
    let decoded = decode_epoch_safety_record_v2_exact(&raw, &context).unwrap();
    assert_eq!(decoded.state(), &state);
    let mut wrong_codec = raw.clone();
    wrong_codec[8..10].copy_from_slice(&1u16.to_be_bytes());
    assert!(decode_epoch_safety_record_v2_exact(&wrong_codec, &context).is_err());

    let decoded = decode_epoch_safety_record_v2_exact(&raw, &context).unwrap();
    let mut cold_budget = Cev0AdmissionBudgetV0::protocol_v0();
    cold_budget.charge_signature_work(7).unwrap();
    let cold_preparation = context
        .epoch()
        .recover_preparation_v2(&mut cold_budget)
        .unwrap();
    assert!(cold_budget.signature_work() > 7);
    let cold_context =
        EpochSafetyStateRecordContextV2::new(&config, cold_preparation, artifact, 41, limits)
            .unwrap();
    assert_eq!(
        epoch_safety_record_context_ref_v2(&context).unwrap(),
        epoch_safety_record_context_ref_v2(&cold_context).unwrap()
    );
    let recovery =
        Core::prepare_epoch_recovery_v2(&decoded, &cold_context, decoded.record_checksum())
            .unwrap();
    assert_eq!(recovery.record_checksum(), decoded.record_checksum());
    assert!(Core::prepare_epoch_recovery_v2(&decoded, &context, [0xa5; 32]).is_err());
}

#[test]
fn codec2_wrong_context_generation_artifact_and_truncation_reject() {
    let (preparation, config, artifact) = build_preparation();
    let limits = minimum_epoch_safety_record_limits_v2(&config, &preparation).unwrap();
    let context =
        EpochSafetyStateRecordContextV2::new(&config, preparation, artifact, 42, limits).unwrap();
    let state =
        SafetyState::from_epoch_activation_v1(&config, context.epoch().clone(), 42).unwrap();
    let raw = encode_epoch_safety_record_v2(&state, &context).unwrap();
    let mut truncated = raw.clone();
    truncated.pop();
    assert!(decode_epoch_safety_record_v2_exact(&truncated, &context).is_err());
    let (other_preparation, other_config, other_artifact) = build_preparation();
    let other_limits =
        minimum_epoch_safety_record_limits_v2(&other_config, &other_preparation).unwrap();
    let other = EpochSafetyStateRecordContextV2::new(
        &other_config,
        other_preparation,
        other_artifact,
        43,
        other_limits,
    )
    .unwrap();
    assert_ne!(
        epoch_safety_record_context_ref_v2(&context).unwrap(),
        epoch_safety_record_context_ref_v2(&other).unwrap()
    );
    assert!(decode_epoch_safety_record_v2_exact(&raw, &other).is_err());

    let (foreign_preparation, foreign_config, _) = build_preparation();
    let foreign_artifact = ValidatedPayloadArtifactRefV0::new(artifact.overlay(), [0x5a; 32]);
    let foreign_limits =
        minimum_epoch_safety_record_limits_v2(&foreign_config, &foreign_preparation).unwrap();
    let foreign = EpochSafetyStateRecordContextV2::new(
        &foreign_config,
        foreign_preparation,
        foreign_artifact,
        42,
        foreign_limits,
    )
    .unwrap();
    assert!(decode_epoch_safety_record_v2_exact(&raw, &foreign).is_err());
}

#[test]
fn codec2_does_not_downgrade_contextual_provenance_to_codec1() {
    let (preparation, config, artifact) = build_preparation();
    let limits = minimum_epoch_safety_record_limits_v2(&config, &preparation).unwrap();
    let context =
        EpochSafetyStateRecordContextV2::new(&config, preparation, artifact, 44, limits).unwrap();
    let contextual_runtime = context.epoch().strict_context().unwrap();
    let legacy_limits =
        minimum_epoch_safety_record_limits_v1(&config, &contextual_runtime).unwrap();
    assert!(EpochSafetyStateRecordContextV1::new(
        &config,
        contextual_runtime,
        artifact,
        44,
        legacy_limits
    )
    .is_err());
    let state =
        SafetyState::from_epoch_activation_v1(&config, context.epoch().clone(), 44).unwrap();
    let raw = encode_epoch_safety_record_v2(&state, &context).unwrap();
    for length in 0..raw.len() {
        assert!(
            decode_epoch_safety_record_v2_exact(&raw[..length], &context).is_err(),
            "accepted truncated record at {length}"
        );
    }
    let legacy_runtime = epoch_state_tests_v1::runtime();
    let legacy_config = epoch_state_tests_v1::config(&legacy_runtime);
    let legacy_artifact = epoch_state_tests_v1::artifact(&legacy_runtime);
    let legacy_limits =
        minimum_epoch_safety_record_limits_v1(&legacy_config, &legacy_runtime).unwrap();
    let legacy_context = EpochSafetyStateRecordContextV1::new(
        &legacy_config,
        legacy_runtime,
        legacy_artifact,
        44,
        legacy_limits,
    )
    .unwrap();
    let mut downgraded = raw;
    downgraded[..8].copy_from_slice(b"TRNMS14E");
    downgraded[8..10].copy_from_slice(&1u16.to_be_bytes());
    assert!(decode_epoch_safety_record_v1_exact(&downgraded, &legacy_context).is_err());
}
