use core::cell::Cell;
use serde_json::Value;
use trnm_consensus_crypto::{
    decode_verify_checkpoint_finality_strict_v0, StrictCheckpointFinalityErrorV0,
    StrictCheckpointFinalityV0, StrictEd25519Verifier,
};
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_consensus_parameters_v0_exact,
    decode_next_epoch_commitment_v0_exact, decode_validator_set_v0_exact, BlockHeader,
    Cev0AdmissionBudgetV0, ConsensusParametersV0, NextEpochCommitmentV0, SignatureBytes,
    SignatureVerifier, SigningRoot, Validator, ValidatorSet,
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

struct Fixture {
    proof: Vec<u8>,
    old_set: ValidatorSet,
    old_parameters: ConsensusParametersV0,
    new_set: ValidatorSet,
    new_parameters: ConsensusParametersV0,
    commitment: NextEpochCommitmentV0,
    header: BlockHeader,
    parent: BlockHeader,
}

fn fixture(profile: &str) -> Fixture {
    let mut corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let row = corpus[profile].as_object_mut().unwrap();
    // Explicitly remove the later certificate. No test of this API is allowed
    // to bootstrap its authority from an already completed handoff.
    assert!(row.remove("handoff").is_some());
    assert!(row.remove("bound_authority").is_some());
    let raw = |section: &str, name: &str| unhex(row[section][name].as_str().unwrap());
    Fixture {
        proof: raw("checkpoint_finality", "raw_finality_proof_cev0_hex"),
        old_set: decode_validator_set_v0_exact(&raw("preheader", "old_validator_set_cev0_hex"))
            .unwrap(),
        old_parameters: decode_consensus_parameters_v0_exact(&raw(
            "preheader",
            "old_parameters_cev0_hex",
        ))
        .unwrap(),
        new_set: decode_validator_set_v0_exact(&raw("preheader", "new_validator_set_cev0_hex"))
            .unwrap(),
        new_parameters: decode_consensus_parameters_v0_exact(&raw(
            "preheader",
            "new_parameters_cev0_hex",
        ))
        .unwrap(),
        commitment: decode_next_epoch_commitment_v0_exact(&raw("preheader", "commitment_cev0_hex"))
            .unwrap(),
        header: decode_block_header_v0_exact(&raw("checkpoint", "header_cev0_hex")).unwrap(),
        parent: decode_block_header_v0_exact(&raw("preheader", "checkpoint_parent_header_cev0_hex"))
            .unwrap(),
    }
}

fn verify(
    f: &Fixture,
    bytes: &[u8],
    expected: &BlockHeader,
    parent: &BlockHeader,
    budget: &mut Cev0AdmissionBudgetV0,
) -> Result<StrictCheckpointFinalityV0, StrictCheckpointFinalityErrorV0> {
    decode_verify_checkpoint_finality_strict_v0(
        bytes,
        &f.old_set,
        &f.old_parameters,
        &f.commitment,
        &f.new_set,
        &f.new_parameters,
        expected,
        parent,
        budget,
    )
}

struct CountStrict(Cell<usize>);

impl SignatureVerifier for CountStrict {
    fn verify(&self, validator: &Validator, root: &SigningRoot, signature: &SignatureBytes) -> bool {
        self.0.set(self.0.get() + 1);
        StrictEd25519Verifier.verify(validator, root, signature)
    }
}

#[test]
fn pre_certificate_positive_and_fallback_need_no_joint_certificate() {
    for profile in ["positive", "authenticated_fallback"] {
        let f = fixture(profile);
        let verified = verify(
            &f,
            &f.proof,
            &f.header,
            &f.parent,
            &mut Cev0AdmissionBudgetV0::protocol_v0(),
        )
        .unwrap();
        assert_eq!(verified.proof().finalized_block().header(), &f.header);
        assert_eq!(verified.kernel().checkpoint_block_id(), f.header.id());
        assert_eq!(verified.kernel().new_epoch(), f.new_set.epoch());
        assert_eq!(verified.proof().try_cev0_bytes().unwrap(), f.proof);
    }
}

#[test]
fn charged_checkpoint_work_equals_actual_strict_verifier_calls_including_proposers() {
    for profile in ["positive", "authenticated_fallback"] {
        let f = fixture(profile);
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        let result = verify(&f, &f.proof, &f.header, &f.parent, &mut budget).unwrap();
        let counted = CountStrict(Cell::new(0));
        result
            .proof()
            .verify(
                &f.old_set,
                None,
                &f.old_parameters,
                f.parent.timestamp_ms(),
                &counted,
            )
            .unwrap();
        assert_eq!(budget.signature_work(), counted.0.get());
        let proof = result.proof();
        let mut per_header = Cev0AdmissionBudgetV0::protocol_v0();
        for (header, parent_time) in [
            (proof.finalized_block(), f.parent.timestamp_ms()),
            (proof.child(), proof.finalized_block().header().timestamp_ms()),
            (proof.grandchild(), proof.child().header().timestamp_ms()),
        ] {
            let before = per_header.signature_work();
            per_header.charge_certified_header(header).unwrap();
            let counted = CountStrict(Cell::new(0));
            header
                .verify(&f.old_set, None, &f.old_parameters, parent_time, &counted)
                .unwrap();
            assert_eq!(per_header.signature_work() - before, counted.0.get());
        }
        assert_eq!(per_header.signature_work(), budget.signature_work());
    }
}

#[test]
fn exact_work_succeeds_and_one_less_rejects_without_partial_charge() {
    let f = fixture("positive");
    let mut measured = Cev0AdmissionBudgetV0::protocol_v0();
    verify(&f, &f.proof, &f.header, &f.parent, &mut measured).unwrap();
    let work = measured.signature_work();
    let mut exact = Cev0AdmissionBudgetV0::new(f.proof.len(), work);
    verify(&f, &f.proof, &f.header, &f.parent, &mut exact).unwrap();
    assert_eq!(exact.signature_work(), work);
    let mut insufficient = Cev0AdmissionBudgetV0::new(f.proof.len(), work - 1);
    assert!(matches!(
        verify(&f, &f.proof, &f.header, &f.parent, &mut insufficient),
        Err(StrictCheckpointFinalityErrorV0::Decode(_))
    ));
    assert_eq!(insufficient.signature_work(), 0);
    assert!(verify(&f, &f.proof, &f.header, &f.parent, &mut exact).is_err());
    assert_eq!(exact.signature_work(), work);
}

#[test]
fn corrupt_proposer_signatures_are_rejected_without_refunding_work() {
    let f = fixture("positive");
    let mut reference = Cev0AdmissionBudgetV0::protocol_v0();
    let verified = verify(&f, &f.proof, &f.header, &f.parent, &mut reference).unwrap();
    for header in [
        verified.proof().finalized_block(),
        verified.proof().child(),
        verified.proof().grandchild(),
    ] {
        let signature = header.proposer_signature().as_bytes();
        let offsets: Vec<_> = f
            .proof
            .windows(signature.len())
            .enumerate()
            .filter_map(|(i, b)| (b == signature).then_some(i))
            .collect();
        assert_eq!(offsets.len(), 1);
        let mut corrupt = f.proof.clone();
        corrupt[offsets[0]] ^= 1;
        let mut budget = Cev0AdmissionBudgetV0::new(f.proof.len(), reference.signature_work());
        assert!(matches!(
            verify(&f, &corrupt, &f.header, &f.parent, &mut budget),
            Err(StrictCheckpointFinalityErrorV0::Consensus(_))
        ));
        assert_eq!(budget.signature_work(), reference.signature_work());
    }
}

#[test]
fn wrong_target_parent_or_configuration_cannot_issue_pre_certificate_result() {
    let f = fixture("positive");
    let other = fixture("authenticated_fallback");
    assert!(verify(
        &f,
        &f.proof,
        &other.header,
        &f.parent,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .is_err());
    assert!(verify(
        &f,
        &f.proof,
        &f.header,
        &other.parent,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .is_err());
    assert!(decode_verify_checkpoint_finality_strict_v0(
        &f.proof,
        &f.old_set,
        &f.old_parameters,
        &f.commitment,
        &f.old_set,
        &f.old_parameters,
        &f.header,
        &f.parent,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .is_err());
}

#[test]
fn incomplete_extra_or_oversized_proof_is_not_repaired() {
    let f = fixture("positive");
    for end in [0, 1, f.proof.len() / 2, f.proof.len() - 1] {
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        assert!(verify(&f, &f.proof[..end], &f.header, &f.parent, &mut budget).is_err());
        assert_eq!(budget.signature_work(), 0);
    }
    let mut extra = f.proof.clone();
    extra.push(0);
    let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
    assert!(verify(&f, &extra, &f.header, &f.parent, &mut budget).is_err());
    assert_eq!(budget.signature_work(), 0);
    let mut too_small = Cev0AdmissionBudgetV0::new(
        f.proof.len() - 1,
        Cev0AdmissionBudgetV0::protocol_v0().maximum_signature_work(),
    );
    assert!(verify(&f, &f.proof, &f.header, &f.parent, &mut too_small).is_err());
    assert_eq!(too_small.signature_work(), 0);
}
