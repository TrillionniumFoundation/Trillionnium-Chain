//! Regression inputs use the existing real-signature checkpoint corpus.
//! These tests do not implement new-set membership/PoP or live epoch handoff.
use serde_json::Value;
use trnm_consensus_signer_journal::{
    HandoffSignerJournalErrorV1, HandoffSignerJournalProfileV1, StrictOldSetHandoffAdmissionV1,
};
use trnm_consensus_types::{
    decode_block_header_v0_exact, decode_checkpoint_finality_proof_v0_exact,
    decode_consensus_parameters_v0_exact, decode_handoff_descriptor_v0_exact,
    decode_next_epoch_commitment_v0_exact, decode_validator_set_v0_exact, BlockHeader,
    CanonicalHandoffSignIntentV1, ConsensusParametersV0, ConsensusPublicKey, FinalityProofV0,
    HandoffDescriptorV0, NextEpochCommitmentV0, Validator, ValidatorId, ValidatorSet,
};

const VECTOR: &str = include_str!(
    "../../../../docs/protocol/poco-bft-v0/vectors/poco-authenticated-checkpoint-handoff-v0.json"
);

struct Fixture {
    old: ValidatorSet,
    new: ValidatorSet,
    old_parameters: ConsensusParametersV0,
    new_parameters: ConsensusParametersV0,
    finality: FinalityProofV0,
    commitment: NextEpochCommitmentV0,
    parent: BlockHeader,
    descriptor: HandoffDescriptorV0,
    author: ValidatorId,
}

fn raw(object: &Value, field: &str) -> Vec<u8> {
    let hex = object[field]
        .as_str()
        .expect("corpus hex string")
        .as_bytes();
    assert_eq!(hex.len() % 2, 0);
    hex.chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16)
                .expect("corpus hex byte")
        })
        .collect()
}

fn fixture() -> Fixture {
    let root: Value = serde_json::from_str(VECTOR).expect("existing corpus");
    let case = &root["positive"];
    let pre = &case["preheader"];
    let old_parameters = decode_consensus_parameters_v0_exact(&raw(pre, "old_parameters_cev0_hex"))
        .expect("old parameters");
    let new_parameters = decode_consensus_parameters_v0_exact(&raw(pre, "new_parameters_cev0_hex"))
        .expect("new parameters");
    let old =
        decode_validator_set_v0_exact(&raw(pre, "old_validator_set_cev0_hex")).expect("old set");
    let new =
        decode_validator_set_v0_exact(&raw(pre, "new_validator_set_cev0_hex")).expect("new set");
    let commitment = decode_next_epoch_commitment_v0_exact(&raw(pre, "commitment_cev0_hex"))
        .expect("commitment");
    let parent = decode_block_header_v0_exact(&raw(pre, "checkpoint_parent_header_cev0_hex"))
        .expect("checkpoint parent");
    let finality = decode_checkpoint_finality_proof_v0_exact(
        &raw(&case["checkpoint_finality"], "raw_finality_proof_cev0_hex"),
        &old,
        &old_parameters,
        &commitment,
        parent.timestamp_ms(),
    )
    .expect("bounded checkpoint finality");
    let descriptor =
        decode_handoff_descriptor_v0_exact(&raw(&case["handoff"], "descriptor_cev0_hex"))
            .expect("descriptor");
    Fixture {
        old,
        new,
        old_parameters,
        new_parameters,
        finality,
        commitment,
        parent,
        descriptor,
        author: ValidatorId::from_bytes(b"validator-a").expect("author"),
    }
}

impl Fixture {
    fn intent(&self) -> CanonicalHandoffSignIntentV1 {
        CanonicalHandoffSignIntentV1::old_set(
            &self.descriptor,
            &self.old,
            &self.new,
            &self.old_parameters,
            &self.new_parameters,
            self.author,
        )
        .expect("original old-role intent")
    }

    fn profile(
        &self,
        old: ValidatorSet,
        new: ValidatorSet,
    ) -> Result<HandoffSignerJournalProfileV1, HandoffSignerJournalErrorV1> {
        HandoffSignerJournalProfileV1::new(
            old,
            new,
            self.old_parameters,
            self.new_parameters,
            self.author,
            [0x51; 32],
            [0x72; 32],
            64,
            16 * 1024,
            32 * 1024 * 1024,
        )
    }

    fn admit(
        &self,
        old: &ValidatorSet,
        new: &ValidatorSet,
    ) -> Result<StrictOldSetHandoffAdmissionV1, HandoffSignerJournalErrorV1> {
        StrictOldSetHandoffAdmissionV1::verify(
            &self.intent(),
            &self.finality,
            &self.commitment,
            old,
            &self.old_parameters,
            new,
            &self.new_parameters,
            &self.parent,
        )
    }
}

fn replace_non_author_key(
    set: &ValidatorSet,
    author: ValidatorId,
    bytes: [u8; 32],
) -> ValidatorSet {
    let mut validators = set.validators().to_vec();
    let index = validators
        .iter()
        .position(|value| value.id() != author)
        .expect("corpus has a non-author member");
    let previous = &validators[index];
    validators[index] = Validator::new(
        previous.id(),
        ConsensusPublicKey::new(bytes),
        previous.voting_power(),
    )
    .expect("nonzero algorithm-neutral key is shape-valid");
    ValidatorSet::new(
        set.genesis_hash(),
        set.chain_id(),
        set.protocol_version(),
        set.epoch(),
        set.consensus_parameters_hash(),
        validators,
    )
    .expect("algorithm-neutral set accepts these unique nonzero bytes")
}

// Compressed identity (small order) and an undecodable point. They are the
// same key classes already covered by trnm-consensus-crypto's own tests.
fn invalid_keys() -> [[u8; 32]; 2] {
    let mut weak = [0; 32];
    weak[0] = 1;
    let mut undecodable = [0; 32];
    undecodable[0] = 2;
    [weak, undecodable]
}

#[test]
fn real_checkpoint_corpus_still_passes_profile_and_old_role_admission() {
    let f = fixture();
    let profile = f
        .profile(f.old.clone(), f.new.clone())
        .expect("strict profile");
    assert!(!profile.production_activation());
    assert!(!profile.safe_vote_authority());
    f.admit(&f.old, &f.new)
        .expect("real signature proof remains accepted");
}

#[test]
fn profile_rejects_bad_keys_outside_author_in_either_set() {
    let f = fixture();
    for key in invalid_keys() {
        let old = replace_non_author_key(&f.old, f.author, key);
        old.validate_against_parameters(&f.old_parameters)
            .expect("shape control");
        assert!(matches!(
            f.profile(old, f.new.clone()),
            Err(HandoffSignerJournalErrorV1::InvalidProfile(
                "old validator keys"
            ))
        ));
        let new = replace_non_author_key(&f.new, f.author, key);
        new.validate_against_parameters(&f.new_parameters)
            .expect("shape control");
        assert!(matches!(
            f.profile(f.old.clone(), new),
            Err(HandoffSignerJournalErrorV1::InvalidProfile(
                "new validator keys"
            ))
        ));
    }
}

#[test]
fn direct_admission_rejects_bad_keys_before_other_binding_checks() {
    let f = fixture();
    let before = (
        f.old.try_cev0_bytes().unwrap(),
        f.new.try_cev0_bytes().unwrap(),
        f.finality.try_cev0_bytes().unwrap(),
    );
    for key in invalid_keys() {
        let old = replace_non_author_key(&f.old, f.author, key);
        assert!(matches!(
            f.admit(&old, &f.new),
            Err(HandoffSignerJournalErrorV1::InvalidAdmission(
                "old validator keys"
            ))
        ));
        let new = replace_non_author_key(&f.new, f.author, key);
        assert!(matches!(
            f.admit(&f.old, &new),
            Err(HandoffSignerJournalErrorV1::InvalidAdmission(
                "new validator keys"
            ))
        ));
    }
    assert_eq!(
        before,
        (
            f.old.try_cev0_bytes().unwrap(),
            f.new.try_cev0_bytes().unwrap(),
            f.finality.try_cev0_bytes().unwrap(),
        )
    );
    // Changed-set fixtures deliberately also invalidate set commitments.
    // The exact error above tests the early key boundary, not a forged proof
    // that the old implementation would otherwise have fully accepted.
}
