use serde_json::Value;
use trnm_consensus_crypto::{
    decode_verify_finality_proof_strict_v0, FinalityExpectationV0, StrictFinalityErrorV0,
    POCO_THREE_CHAIN_PROOF_CLASS_V0,
};
use trnm_consensus_types::{
    decode_checkpoint_finality_proof_v0_exact, decode_consensus_parameters_v0_exact,
    decode_next_epoch_commitment_v0_exact, decode_validator_set_v0_exact, BlockId,
    Cev0AdmissionBudgetV0, ConsensusParametersV0, FinalityProofV0, GenesisHash, Height,
    StateRoot, ValidationError, ValidatorSet,
};

const VECTOR: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/checkpoint-two-seal-kernel-v0.json"
);

struct Fixture {
    bytes: Vec<u8>,
    set: ValidatorSet,
    parameters: ConsensusParametersV0,
    proof: FinalityProofV0,
    expected: FinalityExpectationV0,
    qc_bytes: Vec<u8>,
}

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn raw(value: &Value) -> Vec<u8> {
    hex(value["cev0_hex"].as_str().unwrap())
}

fn fixture() -> Fixture {
    let root: Value = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(root["cryptographic_validity_claimed"], true);
    let valid = &root["valid_objects"];
    let parameters = decode_consensus_parameters_v0_exact(&raw(&valid["consensus_parameters"]))
        .unwrap();
    let set = decode_validator_set_v0_exact(&raw(&valid["old_validator_set"])).unwrap();
    let commitment =
        decode_next_epoch_commitment_v0_exact(&raw(&valid["next_epoch_commitment"])).unwrap();
    let bytes = raw(&valid["checkpoint_finality_proof"]);
    let parent_timestamp_ms = root["fixture"]["authenticated_checkpoint_parent_timestamp_ms"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let proof = decode_checkpoint_finality_proof_v0_exact(
        &bytes,
        &set,
        &parameters,
        &commitment,
        parent_timestamp_ms,
    )
    .unwrap();
    let header = proof.finalized_block().header();
    let expected = FinalityExpectationV0 {
        block_id: header.id(),
        height: header.height(),
        state_root: header.state_root(),
        receipts_root: header.receipts_root(),
        evidence_root: header.evidence_root(),
        parent_id: header.parent_id(),
        parent_height: Height::new(header.height().get() - 1),
        parent_timestamp_ms,
    };
    Fixture {
        bytes,
        set,
        parameters,
        proof,
        expected,
        qc_bytes: raw(&valid["parent_qc"]),
    }
}

fn verify(f: &Fixture, bytes: &[u8], expected: FinalityExpectationV0) -> bool {
    decode_verify_finality_proof_strict_v0(
        POCO_THREE_CHAIN_PROOF_CLASS_V0,
        bytes,
        &f.set,
        &f.parameters,
        expected,
        &mut Cev0AdmissionBudgetV0::for_validator_set(&f.parameters, &f.set),
    )
    .is_ok()
}

#[test]
fn accepts_real_signed_three_chain_and_only_finalizes_oldest_header() {
    let f = fixture();
    let verified = decode_verify_finality_proof_strict_v0(
        POCO_THREE_CHAIN_PROOF_CLASS_V0,
        &f.bytes,
        &f.set,
        &f.parameters,
        f.expected,
        &mut Cev0AdmissionBudgetV0::for_validator_set(&f.parameters, &f.set),
    )
    .unwrap();
    assert_eq!(verified.proof(), &f.proof);
    assert_eq!(verified.finalized_block_id(), f.expected.block_id);
    assert_eq!(verified.finalized_height(), f.expected.height);
    assert_eq!(verified.finalized_state_root(), f.expected.state_root);
    assert_ne!(
        verified.finalized_block_id(),
        f.proof.grandchild().header().id()
    );
}

#[test]
fn rejects_legacy_qc_tc_and_unknown_classes_without_decoder_fallback() {
    let f = fixture();
    for class in ["legacy-live-qc", "qc", "tc", "poco-three-chain-v1", ""] {
        let mut budget = Cev0AdmissionBudgetV0::protocol_v0();
        assert!(matches!(
            decode_verify_finality_proof_strict_v0(
                class,
                &f.bytes,
                &f.set,
                &f.parameters,
                f.expected,
                &mut budget,
            ),
            Err(StrictFinalityErrorV0::UnsupportedProofClass)
        ));
        assert_eq!(budget.signature_work(), 0);
    }
}

#[test]
fn rejects_retargeting_to_newest_qc_or_different_root() {
    let f = fixture();
    let mut expected = f.expected;
    expected.block_id = f.proof.grandchild().header().id();
    assert!(!verify(&f, &f.bytes, expected));
    expected = f.expected;
    expected.state_root = StateRoot::new([0xD1; 32]);
    assert!(!verify(&f, &f.bytes, expected));
    expected = f.expected;
    expected.height = Height::new(expected.height.get() + 1);
    assert!(!verify(&f, &f.bytes, expected));
}

#[test]
fn rejects_wrong_parent_and_height_overflow() {
    let f = fixture();
    let mut expected = f.expected;
    expected.parent_id = BlockId::new([0xD2; 32]);
    assert!(!verify(&f, &f.bytes, expected));
    expected = f.expected;
    expected.parent_height = Height::new(u64::MAX);
    assert!(!verify(&f, &f.bytes, expected));
    expected = f.expected;
    expected.parent_timestamp_ms = u64::MAX;
    assert!(!verify(&f, &f.bytes, expected));
}

#[test]
fn exact_decode_rejects_trailing_bytes_truncation_and_single_qc() {
    let f = fixture();
    let mut trailing = f.bytes.clone();
    trailing.push(0);
    assert!(!verify(&f, &trailing, f.expected));
    for end in [0, 1, f.bytes.len() / 2, f.bytes.len() - 1] {
        assert!(!verify(&f, &f.bytes[..end], f.expected));
    }
    assert!(!verify(&f, &f.qc_bytes, f.expected));
}

#[test]
fn cryptographic_corruption_of_each_proposal_is_rejected_and_charged() {
    let f = fixture();
    for header in [f.proof.finalized_block(), f.proof.child(), f.proof.grandchild()] {
        let signature = header.proposer_signature().as_bytes();
        let positions: Vec<_> = f
            .bytes
            .windows(signature.len())
            .enumerate()
            .filter_map(|(position, bytes)| (bytes == signature).then_some(position))
            .collect();
        assert_eq!(positions.len(), 1, "fixture signature must be unique");
        let mut corrupt = f.bytes.clone();
        corrupt[positions[0]] ^= 1;
        let mut budget = Cev0AdmissionBudgetV0::for_validator_set(&f.parameters, &f.set);
        let error = decode_verify_finality_proof_strict_v0(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &corrupt,
            &f.set,
            &f.parameters,
            f.expected,
            &mut budget,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            StrictFinalityErrorV0::Consensus(ValidationError::InvalidSignature(_))
        ));
        assert!(budget.signature_work() > 0);
    }
}

#[test]
fn signature_and_byte_work_budgets_are_enforced() {
    let f = fixture();
    for mut budget in [
        Cev0AdmissionBudgetV0::new(f.bytes.len() - 1, usize::MAX),
        Cev0AdmissionBudgetV0::new(f.bytes.len(), 0),
    ] {
        assert!(decode_verify_finality_proof_strict_v0(
            POCO_THREE_CHAIN_PROOF_CLASS_V0,
            &f.bytes,
            &f.set,
            &f.parameters,
            f.expected,
            &mut budget,
        )
        .is_err());
    }
}

#[test]
fn proof_cannot_select_its_own_chain_context() {
    let f = fixture();
    let wrong_set = ValidatorSet::new(
        GenesisHash::new([0xE1; 32]),
        f.set.chain_id(),
        f.set.protocol_version(),
        f.set.epoch(),
        f.set.consensus_parameters_hash(),
        f.set.validators().to_vec(),
    )
    .unwrap();
    assert!(decode_verify_finality_proof_strict_v0(
        POCO_THREE_CHAIN_PROOF_CLASS_V0,
        &f.bytes,
        &wrong_set,
        &f.parameters,
        f.expected,
        &mut Cev0AdmissionBudgetV0::protocol_v0(),
    )
    .is_err());
}
