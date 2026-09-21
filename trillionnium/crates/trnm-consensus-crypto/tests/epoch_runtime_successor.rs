use ed25519_dalek::Signer;
use trnm_consensus_crypto::{
    recover_epoch_activation_authority_strict_v0, StrictEpochRuntimeContextV1,
};
use trnm_consensus_types::*;

#[allow(dead_code)]
#[path = "support/epoch_successor_fixture_v1.rs"]
mod epoch_successor_fixture_v1;
use epoch_successor_fixture_v1::*;

#[test]
fn strict_runtime_context_accepts_a_real_repeated_epoch_successor() {
    let predecessor_context =
        StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, old_set, old_params, binding, ancestry) =
        successor_evidence(&predecessor_context);
    let successor = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    assert_eq!(
        old_set,
        *predecessor_context.activation().new_validator_set()
    );
    let successor_context = StrictEpochRuntimeContextV1::from_activation_v1(successor).unwrap();
    let composed = StrictEpochRuntimeContextV1::compose_successor_v1(
        &predecessor_context,
        successor_context,
        &ancestry,
    )
    .unwrap();
    assert_eq!(
        composed.activation().new_validator_set().epoch(),
        Epoch::new(4)
    );
}

#[test]
fn strict_runtime_context_rejects_a_successor_endpoint_substitution() {
    let predecessor_context =
        StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, old_set, old_params, binding, mut ancestry) =
        successor_evidence(&predecessor_context);
    let successor = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let successor_context = StrictEpochRuntimeContextV1::from_activation_v1(successor).unwrap();
    ancestry.pop();
    let error = StrictEpochRuntimeContextV1::compose_successor_v1(
        &predecessor_context,
        successor_context,
        &ancestry,
    )
    .expect_err("a missing successor checkpoint parent must not compose");
    assert!(format!("{error:?}").contains("successor retained ancestry endpoints differ"));
}

#[test]
fn strict_runtime_context_rejects_a_disconnected_successor_ancestry_edge() {
    let predecessor_context =
        StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, old_set, old_params, binding, mut ancestry) =
        successor_evidence(&predecessor_context);
    let successor = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let successor_context = StrictEpochRuntimeContextV1::from_activation_v1(successor).unwrap();
    let broken = ancestry[1].clone();
    ancestry[1] = BlockHeader::new(
        broken.genesis_hash(),
        broken.chain_id(),
        broken.protocol_version(),
        broken.epoch(),
        broken.view(),
        broken.height(),
        broken.block_kind(),
        BlockId::new([0xabu8; 32]),
        broken.proposer_id(),
        broken.validator_set_id(),
        broken.consensus_parameters_hash(),
        broken.payload_root(),
        broken.state_root(),
        broken.receipts_root(),
        broken.evidence_root(),
        broken.timestamp_ms(),
        broken.next_epoch_commitment_hash(),
    )
    .unwrap();
    let error = StrictEpochRuntimeContextV1::compose_successor_v1(
        &predecessor_context,
        successor_context,
        &ancestry,
    )
    .expect_err("a disconnected retained ancestry edge must not compose");
    assert!(format!("{error:?}").contains("successor retained ancestry edge mismatch"));
}

#[test]
fn strict_runtime_context_rejects_a_foreign_epoch_in_retained_successor_ancestry() {
    let predecessor_context =
        StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap();
    let (evidence, old_set, old_params, binding, mut ancestry) =
        successor_evidence(&predecessor_context);
    let successor = recover_epoch_activation_authority_strict_v0(
        evidence.as_preimages(),
        &old_set,
        &old_params,
        binding,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let successor_context = StrictEpochRuntimeContextV1::from_activation_v1(successor).unwrap();
    let child = ancestry[1].clone();
    ancestry[1] = BlockHeader::new(
        child.genesis_hash(),
        child.chain_id(),
        child.protocol_version(),
        predecessor_context.activation().old_validator_set().epoch(),
        child.view(),
        child.height(),
        child.block_kind(),
        child.parent_id(),
        child.proposer_id(),
        child.validator_set_id(),
        child.consensus_parameters_hash(),
        child.payload_root(),
        child.state_root(),
        child.receipts_root(),
        child.evidence_root(),
        child.timestamp_ms(),
        child.next_epoch_commitment_hash(),
    )
    .unwrap();
    let error = StrictEpochRuntimeContextV1::compose_successor_v1(
        &predecessor_context,
        successor_context,
        &ancestry,
    )
    .expect_err("a foreign epoch ancestry child must not compose");
    assert!(format!("{error:?}").contains("successor retained ancestry edge mismatch"));
}

include!("epoch_runtime_successor_contextual.inc");
