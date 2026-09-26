//! Real cryptographic pre-certificate fixtures; no application/custody claim.
#[allow(dead_code)]
#[path = "support/epoch_successor_fixture_v1.rs"]
mod epoch_successor_fixture_v1;

use epoch_successor_fixture_v1::*;
use sha2::{Digest, Sha256};
use trnm_consensus_crypto::{
    decode_verify_successor_epoch_activation_strict_v1,
    decode_verify_successor_pre_handoff_context_strict_v1, verify_pre_handoff_context_strict_v1,
    StrictEpochRuntimeContextV1, StrictPreHandoffContextV1, StrictSuccessorPreHandoffErrorV1,
};
use trnm_consensus_types::*;

struct Inputs {
    proof: Vec<u8>,
    commitment: NextEpochCommitmentV0,
    descriptor: HandoffDescriptorV0,
    new_set: ValidatorSet,
    new_parameters: ConsensusParametersV0,
    ancestry: Vec<BlockHeader>,
}

#[inline(never)]
fn inputs_from_evidence(
    runtime: &StrictEpochRuntimeContextV1,
    mut evidence: EpochActivationEvidenceBytesV0,
    ancestry: Vec<BlockHeader>,
) -> Inputs {
    // The fixture's complete certificate supplies the exact descriptor only.
    // The tested producer receives no certificate or role signatures at all.
    let decoded = Box::new(
        decode_epoch_activation_evidence_with_context_v1_exact(
            evidence.as_preimages(),
            runtime.structural_context(),
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap(),
    );
    let result = Inputs {
        proof: evidence.old_checkpoint_finality.clone(),
        commitment: *decoded.next_epoch_commitment(),
        descriptor: decoded
            .authorization_kernel()
            .handoff_certificate()
            .descriptor()
            .clone(),
        new_set: decoded.new_validator_set().clone(),
        new_parameters: *decoded.new_consensus_parameters(),
        ancestry,
    };
    evidence.authorization_kernel.clear();
    assert!(evidence.authorization_kernel.is_empty());
    result
}

#[inline(never)]
fn fixture(
    runtime: &StrictEpochRuntimeContextV1,
    timeout: bool,
    bad: SuccessorBadSignature,
) -> Inputs {
    let (evidence, _, _, _, ancestry) = successor_evidence_variant(runtime, timeout, bad);
    inputs_from_evidence(runtime, evidence, ancestry)
}

fn verify(
    runtime: &StrictEpochRuntimeContextV1,
    inputs: &Inputs,
    budget: &mut Cev0AdmissionBudgetV0,
) -> core::result::Result<StrictPreHandoffContextV1, StrictSuccessorPreHandoffErrorV1> {
    decode_verify_successor_pre_handoff_context_strict_v1(
        runtime.activation(),
        &inputs.ancestry,
        &inputs.proof,
        &inputs.commitment,
        &inputs.descriptor,
        &inputs.new_set,
        &inputs.new_parameters,
        budget,
    )
}

fn aggregate_bytes(runtime: &StrictEpochRuntimeContextV1, inputs: &Inputs) -> usize {
    inputs.proof.len()
        + inputs.commitment.try_cev0_bytes().unwrap().len()
        + inputs.descriptor.try_cev0_bytes().unwrap().len()
        + runtime
            .activation()
            .new_validator_set()
            .try_cev0_bytes()
            .unwrap()
            .len()
        + runtime
            .activation()
            .new_consensus_parameters()
            .canonical_bytes()
            .len()
        + inputs.new_set.try_cev0_bytes().unwrap().len()
        + inputs.new_parameters.canonical_bytes().len()
        + inputs
            .ancestry
            .iter()
            .map(|h| h.try_cev0_bytes().unwrap().len())
            .sum::<usize>()
}

#[test]
fn signed_contextual_checkpoint_without_joint_certificate_accepts_and_reverifies() {
    let runtime = Box::new(StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap());
    let inputs = fixture(&runtime, true, SuccessorBadSignature::None);
    let parent = inputs.ancestry.last().unwrap();
    let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
    let proof = Box::new(
        decode_epoch_runtime_finality_proof_v1_exact_with_budget(
            &inputs.proof,
            runtime.structural_context(),
            parent.timestamp_ms(),
            &mut measured,
        )
        .unwrap(),
    );
    for certified in [proof.finalized_block(), proof.child(), proof.grandchild()] {
        let timeout = certified.timeout_certificate().unwrap();
        assert_eq!(timeout.referenced_qcs().len(), 2);
        assert!(timeout
            .referenced_qcs()
            .contains(runtime.anchor_reference()));
        assert_eq!(runtime.anchor_reference().qc_ref().view(), View::new(0));
        assert_eq!(
            runtime.anchor_reference().qc_ref().block_id(),
            inputs.ancestry[0].id()
        );
    }
    assert!(decode_finality_proof_v0_exact(
        &inputs.proof,
        runtime.activation().new_validator_set(),
        runtime.activation().new_consensus_parameters(),
        parent.timestamp_ms(),
    )
    .is_err());
    assert!(verify_pre_handoff_context_strict_v1(
        &proof,
        &inputs.commitment,
        &inputs.descriptor,
        runtime.activation().new_validator_set(),
        runtime.activation().new_consensus_parameters(),
        &inputs.new_set,
        &inputs.new_parameters,
        parent,
    )
    .is_err());

    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    budget.charge_signature_work(7).unwrap();
    let verified = verify(&runtime, &inputs, &mut budget).unwrap();
    assert_eq!(budget.signature_work(), 7 + measured.signature_work());
    assert_eq!(verified.descriptor(), &inputs.descriptor);
    assert_eq!(verified.checkpoint_parent_block_id(), parent.id());
    assert_eq!(
        verified.checkpoint_parent_timestamp_ms(),
        parent.timestamp_ms()
    );
    assert_eq!(verified.checkpoint_finality_proof_id(), proof.id());
    assert_eq!(
        verified.old_validator_set(),
        runtime.activation().new_validator_set()
    );
    assert_eq!(verified.new_validator_set(), &inputs.new_set);
    let recovered = verify(&runtime, &inputs, &mut Cev0AdmissionBudgetV0::protocol_v0()).unwrap();
    assert_eq!(verified, recovered);
}

#[test]
fn every_canonical_nested_signature_failure_keeps_one_proof_charge() {
    let runtime = Box::new(StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap());
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
    ] {
        let inputs = fixture(&runtime, true, bad);
        let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
        let proof = Box::new(
            decode_epoch_runtime_finality_proof_v1_exact_with_budget(
                &inputs.proof,
                runtime.structural_context(),
                inputs.ancestry.last().unwrap().timestamp_ms(),
                &mut measured,
            )
            .unwrap(),
        );
        // Specialized M00 relations deliberately carry no signature authority.
        proof
            .validate_checkpoint_two_seal_structure_v1(
                runtime.activation().new_validator_set(),
                runtime.activation().new_consensus_parameters(),
                &inputs.commitment,
            )
            .unwrap();
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        budget.charge_signature_work(7).unwrap();
        assert!(
            matches!(
                verify(&runtime, &inputs, &mut budget),
                Err(StrictSuccessorPreHandoffErrorV1::Consensus(_))
            ),
            "{bad:?}"
        );
        assert!(measured.signature_work() > 0);
        assert_eq!(
            budget.signature_work(),
            7 + measured.signature_work(),
            "{bad:?}"
        );
    }
}

#[test]
fn exact_ancestry_descriptor_commitment_and_context_are_required_before_crypto() {
    let runtime = Box::new(StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap());
    let mut inputs = fixture(&runtime, true, SuccessorBadSignature::None);
    let original = inputs.ancestry.clone();
    for ancestry in [
        Vec::new(),
        original[..1].to_vec(),
        original[1..].to_vec(),
        original[..original.len() - 1].to_vec(),
        vec![original[0].clone(); 257],
        {
            let mut swapped = original.clone();
            swapped.swap(1, 2);
            swapped
        },
    ] {
        inputs.ancestry = ancestry;
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        budget.charge_signature_work(7).unwrap();
        assert!(verify(&runtime, &inputs, &mut budget).is_err());
        assert_eq!(budget.signature_work(), 7);
    }
    inputs.ancestry = original;
    let descriptor = inputs.descriptor.clone();
    for changed in [
        {
            let mut fields = descriptor.fields().clone();
            fields.checkpoint_state_root = StateRoot::new([99; 32]);
            fields
        },
        {
            let mut fields = descriptor.fields().clone();
            fields.terminal_old_qc_digest = CertificateId::new([99; 32]);
            fields
        },
        {
            let mut fields = descriptor.fields().clone();
            fields.terminal_old_view = View::new(fields.terminal_old_view.get() + 1);
            fields
        },
    ] {
        inputs.descriptor = HandoffDescriptorV0::new(changed).unwrap();
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        assert!(verify(&runtime, &inputs, &mut budget).is_err());
        assert_eq!(budget.signature_work(), 0);
    }
    inputs.descriptor = descriptor;
    let commitment = inputs.commitment;
    let mut fields = commitment.fields();
    fields.snapshot_state_root = StateRoot::new([99; 32]);
    inputs.commitment = NextEpochCommitmentV0::new(fields).unwrap();
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    assert!(verify(&runtime, &inputs, &mut budget).is_err());
    assert_eq!(budget.signature_work(), 0);
    inputs.commitment = commitment;

    let (evidence, _, _, _, ancestry) =
        successor_evidence_variant(&runtime, true, SuccessorBadSignature::None);
    let foreign = decode_verify_successor_epoch_activation_strict_v1(
        runtime.activation(),
        &ancestry,
        evidence.as_preimages(),
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .unwrap();
    let foreign = Box::new(StrictEpochRuntimeContextV1::from_activation_v1(foreign).unwrap());
    assert!(verify(&foreign, &inputs, &mut budget).is_err());
    assert_eq!(budget.signature_work(), 0);

    let (evidence, _, _, _, ancestry) = successor_evidence_with_ancestry_variant(
        &runtime,
        false,
        SuccessorBadSignature::None,
        true,
    );
    let repeated = inputs_from_evidence(&runtime, evidence, ancestry);
    assert!(matches!(
        verify(&runtime, &repeated, &mut budget),
        Err(StrictSuccessorPreHandoffErrorV1::Ancestry(_))
    ));
    assert_eq!(budget.signature_work(), 0);
}

#[test]
fn aggregate_bytes_shared_work_and_canonical_proof_limits_are_exact() {
    let runtime = Box::new(StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap());
    let mut inputs = fixture(&runtime, true, SuccessorBadSignature::None);
    let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
    verify(&runtime, &inputs, &mut measured).unwrap();
    let cost = measured.signature_work();
    let bytes = aggregate_bytes(&runtime, &inputs);
    let mut exact = Cev0AdmissionBudgetV0::new(bytes, cost + 7);
    exact.charge_signature_work(7).unwrap();
    verify(&runtime, &inputs, &mut exact).unwrap();
    assert_eq!(exact.signature_work(), cost + 7);
    for mut budget in [
        Cev0AdmissionBudgetV0::new(bytes - 1, cost + 7),
        Cev0AdmissionBudgetV0::new(bytes, cost + 6),
    ] {
        budget.charge_signature_work(7).unwrap();
        assert!(verify(&runtime, &inputs, &mut budget).is_err());
        assert_eq!(budget.signature_work(), 7);
    }
    let mut zero = Cev0AdmissionBudgetV0::new(bytes, 0);
    assert!(verify(&runtime, &inputs, &mut zero).is_err());
    assert_eq!(zero.signature_work(), 0);
    inputs.proof.push(0);
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    budget.charge_signature_work(7).unwrap();
    assert!(verify(&runtime, &inputs, &mut budget).is_err());
    assert_eq!(budget.signature_work(), 7);
}

#[test]
fn original_context_free_route_keeps_its_exact_binding_and_new_route_is_distinct() {
    let runtime = Box::new(StrictEpochRuntimeContextV1::from_activation_v1(predecessor()).unwrap());
    let inputs = fixture(&runtime, false, SuccessorBadSignature::None);
    let parent = inputs.ancestry.last().unwrap();
    let old_set = runtime.activation().new_validator_set();
    let old_parameters = runtime.activation().new_consensus_parameters();
    let proof = Box::new(
        decode_finality_proof_v0_exact(
            &inputs.proof,
            old_set,
            old_parameters,
            parent.timestamp_ms(),
        )
        .unwrap(),
    );
    let old = verify_pre_handoff_context_strict_v1(
        &proof,
        &inputs.commitment,
        &inputs.descriptor,
        old_set,
        old_parameters,
        &inputs.new_set,
        &inputs.new_parameters,
        parent,
    )
    .unwrap();
    let mut expected = Sha256::new();
    expected.update(b"trnm.poco-bft.pre-handoff-context.v1");
    for hash in [
        proof.id().as_bytes(),
        inputs.descriptor.id().as_bytes(),
        inputs.commitment.id().as_bytes(),
        old_set.id().as_bytes(),
        inputs.new_set.id().as_bytes(),
        old_parameters.hash().as_bytes(),
        inputs.new_parameters.hash().as_bytes(),
        parent.id().as_bytes(),
    ] {
        expected.update(hash);
    }
    let expected: [u8; 32] = expected.finalize().into();
    assert_eq!(old.binding_ref(), expected);
    let successor = verify(&runtime, &inputs, &mut Cev0AdmissionBudgetV0::protocol_v0()).unwrap();
    assert_eq!(old.descriptor(), successor.descriptor());
    assert_ne!(old.binding_ref(), successor.binding_ref());
}
