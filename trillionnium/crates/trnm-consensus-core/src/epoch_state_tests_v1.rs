use crate::*;
use alloc::vec::Vec;
use trnm_consensus_crypto::{
    recover_epoch_activation_authority_strict_v0, StrictEd25519Verifier,
    StrictEpochRuntimeContextV1,
};
use trnm_consensus_types::*;

fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
pub(crate) fn runtime() -> StrictEpochRuntimeContextV1 {
    let corpus: serde_json::Value = serde_json::from_str(include_str!("../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json")).unwrap();
    let case = &corpus["positive"];
    let raw = |section: &str, field: &str| bytes(case[section][field].as_str().unwrap());
    let evidence = EpochActivationEvidenceBytesV0 {
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
    let old = decode_validator_set_v0_exact(&evidence.old_validator_set).unwrap();
    let params = decode_consensus_parameters_v0_exact(&evidence.old_consensus_parameters).unwrap();
    let activation = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old,
        &params,
        bytes("4ba70b831d3bd70a1be8669f654ac42148017fca0b83f84e999ac532b9c70e4f")
            .try_into()
            .unwrap(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    StrictEpochRuntimeContextV1::from_activation_v1(activation).unwrap()
}
pub(crate) fn config(runtime: &StrictEpochRuntimeContextV1) -> CoreConfig {
    let set = runtime.structural_context().new_validator_set();
    CoreConfig::new(
        set.validators()[0].id(),
        set.clone(),
        *runtime.structural_context().new_parameters(),
        0,
        32,
        32,
    )
    .unwrap()
}
pub(crate) fn artifact(runtime: &StrictEpochRuntimeContextV1) -> ValidatedPayloadArtifactRefV0 {
    let c = runtime
        .activation()
        .old_checkpoint_finality()
        .finalized_block()
        .header();
    // Inert fixture P identifiers; these are not an actual native receipt.
    ValidatedPayloadArtifactRefV0::new(
        BlockIdOverlayRefV0::new(c.id(), c.parent_id(), [0x71; 32]),
        [0x72; 32],
    )
}

#[test]
fn epoch14_record_retains_real_old_checkpoint_and_separate_new_anchor() {
    let runtime = runtime();
    let config = config(&runtime);
    let limits = minimum_epoch_safety_record_limits_v1(&config, &runtime).unwrap();
    let context = EpochSafetyStateRecordContextV1::new(
        &config,
        runtime,
        artifact(&self::runtime()),
        2,
        limits,
    )
    .unwrap();
    let state =
        SafetyState::from_epoch_activation_v1(&config, context.epoch().clone(), 42).unwrap();
    Core::validate_persisted_state_v0(&config, &state, &StrictEd25519Verifier).unwrap();
    let raw = encode_epoch_safety_record_v1(&state, &context).unwrap();
    assert_eq!(&raw[..8], b"TRNMS14E");
    let decoded = decode_epoch_safety_record_v1_exact(&raw, &context).unwrap();
    assert_eq!(decoded.state(), &state);
    let checkpoint = context.epoch().checkpoint_header();
    let terminal = context.epoch().terminal_old_header();
    assert_eq!(state.finalized().block_id(), checkpoint.id());
    assert_eq!(state.application_applied(), state.finalized());
    assert_eq!(
        state.qualified_finalized_v1(config.validator_set()).epoch(),
        checkpoint.epoch()
    );
    assert_eq!(state.high_qc().qc_ref().block_id(), terminal.id());
    assert_eq!(state.high_qc().qc_ref().view(), View::new(0));
    assert_ne!(terminal.view(), View::new(0));
    assert!(state.last_finalization().is_none());
    assert!(state.finalization_queue().is_empty());
    assert!(Core::recover(config.clone(), state.clone(), &StrictEd25519Verifier).is_err());
    assert!(SafetyStateRecordContextV0::new(&config, [0x51; 32], limits).is_err());
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(decode_epoch_safety_record_v1_exact(&trailing, &context).is_err());
    let mut substituted = raw.clone();
    substituted[64] ^= 1;
    assert!(decode_epoch_safety_record_v1_exact(&substituted, &context).is_err());
    let other = EpochSafetyStateRecordContextV1::new(
        &config,
        self::runtime(),
        artifact(&self::runtime()),
        3,
        limits,
    )
    .unwrap();
    assert!(decode_epoch_safety_record_v1_exact(&raw, &other).is_err());
    let mut relabeled = state.clone();
    relabeled.set_finalized(FinalizedTip::new(
        terminal.height(),
        View::new(0),
        terminal.id(),
        terminal.timestamp_ms(),
    ));
    relabeled.set_application_applied(relabeled.finalized());
    assert!(
        Core::validate_persisted_state_v0(&config, &relabeled, &StrictEd25519Verifier).is_err()
    );
}

#[test]
fn epoch_safety_rules_orders_the_anchor_without_relabeling_old_finality() {
    use trnm_consensus_safety_rules::{
        FinalizedBlockRefV1, PureHotStuffSafetyKernelV1, SafetyRulesContextV1,
        SafetyRulesStateSeedV1, SafetyRulesStateV1,
    };
    let runtime = runtime();
    let author = runtime
        .structural_context()
        .new_validator_set()
        .validators()[0]
        .id();
    let finalized = FinalizedBlockRefV1::from_header(
        runtime
            .activation()
            .old_checkpoint_finality()
            .finalized_block()
            .header(),
    )
    .unwrap();
    let terminal =
        FinalizedBlockRefV1::from_header(runtime.activation().terminal_old_header()).unwrap();
    let anchor = runtime.anchor_reference().clone();
    assert!(finalized.view() > anchor.qc_ref().view());
    let context = SafetyRulesContextV1::new_epoch_runtime_v1(runtime, author, 0, 64).unwrap();
    let state = SafetyRulesStateV1::new(
        &context,
        SafetyRulesStateSeedV1::new(
            View::new(1),
            None,
            None,
            anchor.clone(),
            anchor.clone(),
            finalized,
            42,
        ),
        &StrictEd25519Verifier,
    )
    .unwrap();
    let transition =
        PureHotStuffSafetyKernelV1::prepare_timeout(&context, &state, &StrictEd25519Verifier)
            .unwrap();
    assert_eq!(transition.successor_state().finalized(), finalized);
    assert_eq!(transition.successor_state().revision(), 43);
    assert_eq!(transition.successor_state().high_qc(), &anchor);
    assert!(SafetyRulesStateV1::new(
        &context,
        SafetyRulesStateSeedV1::new(
            View::new(1),
            None,
            None,
            anchor.clone(),
            anchor,
            terminal,
            42
        ),
        &StrictEd25519Verifier
    )
    .is_err());
}
