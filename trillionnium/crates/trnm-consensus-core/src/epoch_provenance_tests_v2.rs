use super::*;
use crate::{EpochPreparationEntryV2, EpochPreparationV2};
use alloc::vec::Vec;
use trnm_consensus_crypto::recover_successor_epoch_activation_authority_strict_v1;
use trnm_consensus_types::EpochActivationEvidenceBytesV0;

use crate::epoch_successor_fixture_tests_v2 as fixture;

struct Chain {
    roots: Vec<EpochActivationEvidenceBytesV0>,
    headers: Vec<Vec<Vec<u8>>>,
    bindings: Vec<[u8; 32]>,
    root_set: ValidatorSet,
    root_parameters: ConsensusParametersV0,
}
impl Chain {
    fn genuine(mixed_second: bool) -> Self {
        let mut runtime =
            StrictEpochRuntimeContextV1::from_activation_v1(fixture::predecessor()).unwrap();
        let mut chain = Self {
            roots: alloc::vec![runtime.evidence_bytes().clone()],
            headers: alloc::vec![Vec::new()],
            bindings: alloc::vec![*runtime.activation().binding_ref().as_bytes()],
            root_set: runtime.activation().old_validator_set().clone(),
            root_parameters: *runtime.activation().old_consensus_parameters(),
        };
        for mixed in [mixed_second, true] {
            let (evidence, _, _, binding, ancestry) = fixture::successor_evidence_variant(
                &runtime,
                mixed,
                fixture::SuccessorBadSignature::None,
            );
            let activation = recover_successor_epoch_activation_authority_strict_v1(
                runtime.activation(),
                &ancestry,
                evidence.as_preimages(),
                binding,
                &mut Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
            runtime = StrictEpochRuntimeContextV1::from_activation_v1(activation).unwrap();
            chain.roots.push(evidence);
            chain.headers.push(
                ancestry
                    .iter()
                    .map(|header| header.try_cev0_bytes().unwrap())
                    .collect(),
            );
            chain.bindings.push(binding);
        }
        chain
    }
    fn prepare(&self, count: usize) -> EpochPreparationV2 {
        let headers: Vec<Vec<&[u8]>> = self.headers[..count]
            .iter()
            .map(|interval| interval.iter().map(Vec::as_slice).collect())
            .collect();
        let entries: Vec<_> = (0..count)
            .map(|i| EpochPreparationEntryV2 {
                binding_ref: self.bindings[i],
                retained_ancestry: &headers[i],
                evidence: self.roots[i].as_preimages(),
            })
            .collect();
        crate::prepare_epoch_handoff_evidence_v2(
            &entries,
            &self.root_set,
            &self.root_parameters,
            self.bindings[0],
            self.bindings[count - 1],
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap()
    }
    fn state(&self, count: usize) -> EpochCoreStateV1 {
        let prep = self.prepare(count);
        let checkpoint = prep
            .authority_v2()
            .old_checkpoint_finality()
            .finalized_block()
            .header();
        let artifact = ValidatedPayloadArtifactRefV0::new(
            crate::BlockIdOverlayRefV0::new(checkpoint.id(), checkpoint.parent_id(), [71; 32]),
            [72; 32],
        );
        EpochCoreStateV1::from_preparation_v2(prep, artifact, count as u64 + 1)
            .unwrap()
            .0
    }
}

#[test]
fn full_provenance_requires_one_exact_appended_entry_across_three_real_activations() {
    let chain = Chain::genuine(true);
    let one = chain.state(1);
    let two = chain.state(2);
    let three = chain.state(3);
    one.check_predecessor_provenance_v2(None).unwrap();
    assert!(two.check_predecessor_provenance_v2(None).is_err());
    two.check_predecessor_provenance_v2(Some(&one)).unwrap();
    three.check_predecessor_provenance_v2(Some(&two)).unwrap();
    assert!(three.check_predecessor_provenance_v2(Some(&one)).is_err());
    assert!(two.check_predecessor_provenance_v2(Some(&two)).is_err());
    assert!(one.check_predecessor_provenance_v2(Some(&two)).is_err());
    assert_eq!(
        *three
            .strict_context()
            .unwrap()
            .activation()
            .binding_ref()
            .as_bytes(),
        chain.bindings[2]
    );
}

#[test]
fn a_different_validly_signed_prefix_cannot_replace_the_source_history() {
    let original = Chain::genuine(true);
    let alternative = Chain::genuine(false);
    assert_eq!(original.bindings[0], alternative.bindings[0]);
    assert_ne!(original.bindings[1], alternative.bindings[1]);
    let old = original.state(2);
    let target = alternative.state(3);
    target.strict_context().unwrap();
    assert!(target.check_predecessor_provenance_v2(Some(&old)).is_err());
}

#[test]
fn legacy_source_must_match_the_first_entry_and_cannot_skip_transitions() {
    let chain = Chain::genuine(true);
    let runtime = StrictEpochRuntimeContextV1::from_activation_v1(fixture::predecessor()).unwrap();
    let legacy =
        EpochCoreStateV1::from_strict(&runtime, crate::epoch_state_tests_v1::artifact(&runtime), 2)
            .unwrap();
    chain
        .state(2)
        .check_predecessor_provenance_v2(Some(&legacy))
        .unwrap();
    assert!(chain
        .state(3)
        .check_predecessor_provenance_v2(Some(&legacy))
        .is_err());
    assert!(chain
        .state(1)
        .check_predecessor_provenance_v2(Some(&legacy))
        .is_err());
}
