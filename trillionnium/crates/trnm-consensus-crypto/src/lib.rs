#![no_std]
#![forbid(unsafe_code)]
//! Strict, verification-only cryptographic boundary for PoCO-BFT v0.
//!
//! This crate deliberately exposes no signing or private-key API. Consensus
//! messages are verified as RFC 8032 Ed25519 signatures over the exact raw
//! 32-byte [`trnm_consensus_types::SigningRoot`].

extern crate alloc;

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, VerifyingKey};
use trnm_consensus_types::{
    ConsensusPublicKey, Result, SignatureBytes, SignatureVerifier, SigningRoot, ValidationError,
    Validator, ValidatorSet,
};

mod epoch_transition;

pub use epoch_transition::{
    verify_same_version_epoch_activation_authority_strict_v0,
    verify_same_version_epoch_transition_strict_v0, StrictEpochActivationBindingRefV0,
    StrictSameVersionEpochActivationAuthorityV0, StrictSameVersionEpochTransitionV0,
};

/// Stateless strict Ed25519 verifier for PoCO-BFT v0 consensus roots.
///
/// Public keys must decode as Ed25519 compressed points. `verify_strict`
/// additionally rejects non-canonical signature scalars/R encodings and
/// small-order public-key/signature points. Any decode or verification error
/// fails closed.
#[derive(Debug, Clone, Copy, Default)]
pub struct StrictEd25519Verifier;

/// Production admission wrapper for a validator set whose consensus keys have
/// all passed the strict Ed25519 key-shape boundary.
///
/// `trnm-consensus-types::ValidatorSet::new` intentionally remains an
/// algorithm-neutral CEV0 constructor: it rejects zero/duplicate keys, while
/// the protocol's generic decoder leaves curve-point interpretation to the
/// selected cryptographic profile.  A node which is about to commission or
/// activate an Ed25519 validator set must consume this wrapper (or call
/// [`validate_validator_set_strict_ed25519_v0`]) before handing the set to
/// Core or an epoch-transition authority.
///
/// This is an admission proof, not a new wire/protocol type.  It carries the
/// exact original set and does not grant signing, epoch, or Core authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictValidatorSetV0(ValidatorSet);

impl StrictValidatorSetV0 {
    /// Validates every consensus key using the strict Ed25519 profile and
    /// retains the exact set only after all keys pass.
    pub fn new(validator_set: ValidatorSet) -> Result<Self> {
        validate_validator_set_strict_ed25519_v0(&validator_set)?;
        Ok(Self(validator_set))
    }

    /// Borrows the exact admitted validator set.
    pub const fn validator_set(&self) -> &ValidatorSet {
        &self.0
    }

    /// Releases the exact admitted set.  The caller must keep this value on
    /// the same strict-admission path when constructing a live node.
    pub fn into_validator_set(self) -> ValidatorSet {
        self.0
    }
}

impl StrictEd25519Verifier {
    /// Admits one validator set for an Ed25519 production boundary.
    ///
    /// This method is deliberately explicit instead of being hidden behind
    /// the generic [`SignatureVerifier`] trait.  A permissive test verifier
    /// therefore cannot accidentally claim strict key admission.
    pub fn admit_validator_set_v0(
        &self,
        validator_set: ValidatorSet,
    ) -> Result<StrictValidatorSetV0> {
        StrictValidatorSetV0::new(validator_set)
    }

    /// Checks all consensus public keys in an existing set without taking
    /// ownership of it.
    pub fn validate_validator_set_v0(&self, validator_set: &ValidatorSet) -> Result<()> {
        validate_validator_set_strict_ed25519_v0(validator_set)
    }
}

const INVALID_ED25519_PUBLIC_KEY: &str =
    "consensus public key is not a decodable Ed25519 compressed point";
const WEAK_ED25519_PUBLIC_KEY: &str = "consensus public key is a weak/small-order Ed25519 point";

/// Validates the exact CEV0 validator set against the production Ed25519
/// admission profile.
///
/// The generic CEV0 constructor intentionally does not depend on a concrete
/// cryptographic backend.  This function is the corresponding explicit
/// profile boundary: it first rechecks the set's shape and then rejects every
/// undecodable or weak public key, including keys which happen not to appear
/// in a particular QC.
pub fn validate_validator_set_strict_ed25519_v0(validator_set: &ValidatorSet) -> Result<()> {
    validator_set.validate_shape()?;
    for validator in validator_set.validators() {
        validate_consensus_public_key_strict_ed25519_v0(&validator.consensus_key())?;
    }
    Ok(())
}

/// Validates one consensus public key under the strict Ed25519 profile.
pub fn validate_consensus_public_key_strict_ed25519_v0(
    public_key: &ConsensusPublicKey,
) -> Result<()> {
    let bytes = *public_key.as_bytes();
    let compressed = CompressedEdwardsY(bytes);
    let point = compressed
        .decompress()
        .ok_or(ValidationError::InvalidValidatorSet(
            INVALID_ED25519_PUBLIC_KEY,
        ))?;
    if point.compress().to_bytes() != bytes {
        return Err(ValidationError::InvalidValidatorSet(
            INVALID_ED25519_PUBLIC_KEY,
        ));
    }
    let verifying_key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| ValidationError::InvalidValidatorSet(INVALID_ED25519_PUBLIC_KEY))?;
    if point.is_small_order() || verifying_key.is_weak() {
        return Err(ValidationError::InvalidValidatorSet(
            WEAK_ED25519_PUBLIC_KEY,
        ));
    }
    Ok(())
}

impl SignatureVerifier for StrictEd25519Verifier {
    fn verify(
        &self,
        validator: &Validator,
        signing_root: &SigningRoot,
        signature: &SignatureBytes,
    ) -> bool {
        let public_key_bytes = validator.consensus_key();
        let Ok(public_key) = VerifyingKey::from_bytes(public_key_bytes.as_bytes()) else {
            return false;
        };
        let signature = Signature::from_bytes(signature.as_bytes());
        public_key
            .verify_strict(signing_root.as_bytes(), &signature)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use trnm_consensus_types::{
        ChainId, ConsensusParametersHash, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        SignatureBytes, SignatureVerifier, SigningRoot, Validator, ValidatorId, ValidatorSet,
        VotingPower,
    };

    use super::{
        validate_consensus_public_key_strict_ed25519_v0, validate_validator_set_strict_ed25519_v0,
        StrictEd25519Verifier, StrictValidatorSetV0,
    };

    // RFC 8032 section 7.1, TEST 1. This fixture seed never leaves test code.
    const RFC8032_TEST_1_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const VOTE_ROOT: [u8; 32] = [
        0x90, 0xed, 0x74, 0x5f, 0x8b, 0xc3, 0x83, 0x10, 0xe5, 0x2e, 0xab, 0xae, 0x53, 0x55, 0x01,
        0x39, 0x14, 0xd7, 0x87, 0x08, 0x7f, 0xa5, 0xc6, 0xab, 0x6e, 0x42, 0xfd, 0x7a, 0xe6, 0x98,
        0xde, 0xd1,
    ];
    const EXPECTED_PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    const EXPECTED_SIGNATURE: [u8; 64] = [
        0x32, 0x4a, 0x7b, 0x30, 0x5a, 0xb4, 0x28, 0xde, 0x6f, 0x7b, 0xdd, 0xe9, 0x56, 0xb7, 0xc9,
        0xf6, 0xf5, 0xcf, 0x0a, 0x92, 0xbd, 0xd2, 0x1b, 0x0b, 0x2b, 0x5b, 0x0b, 0x16, 0x6f, 0xa6,
        0x14, 0x11, 0x40, 0x3e, 0xd1, 0xa3, 0xb5, 0xd4, 0xf2, 0xdc, 0x23, 0x4a, 0xc7, 0x8b, 0x11,
        0xa5, 0xca, 0x5f, 0x8d, 0x8f, 0xae, 0x54, 0x8c, 0x22, 0xb5, 0x38, 0x68, 0x18, 0xf3, 0x28,
        0xe5, 0x03, 0xbd, 0x0d,
    ];
    const WRONG_ROOT: [u8; 32] = [
        0x91, 0xed, 0x74, 0x5f, 0x8b, 0xc3, 0x83, 0x10, 0xe5, 0x2e, 0xab, 0xae, 0x53, 0x55, 0x01,
        0x39, 0x14, 0xd7, 0x87, 0x08, 0x7f, 0xa5, 0xc6, 0xab, 0x6e, 0x42, 0xfd, 0x7a, 0xe6, 0x98,
        0xde, 0xd1,
    ];
    const MUTATED_SIGNATURE: [u8; 64] = [
        0x33, 0x4a, 0x7b, 0x30, 0x5a, 0xb4, 0x28, 0xde, 0x6f, 0x7b, 0xdd, 0xe9, 0x56, 0xb7, 0xc9,
        0xf6, 0xf5, 0xcf, 0x0a, 0x92, 0xbd, 0xd2, 0x1b, 0x0b, 0x2b, 0x5b, 0x0b, 0x16, 0x6f, 0xa6,
        0x14, 0x11, 0x40, 0x3e, 0xd1, 0xa3, 0xb5, 0xd4, 0xf2, 0xdc, 0x23, 0x4a, 0xc7, 0x8b, 0x11,
        0xa5, 0xca, 0x5f, 0x8d, 0x8f, 0xae, 0x54, 0x8c, 0x22, 0xb5, 0x38, 0x68, 0x18, 0xf3, 0x28,
        0xe5, 0x03, 0xbd, 0x0d,
    ];
    const UNDECODABLE_PUBLIC_KEY: [u8; 32] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    const SMALL_ORDER_PUBLIC_KEY: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    fn validator(public_key: [u8; 32]) -> Validator {
        Validator::new(
            ValidatorId::from_bytes(b"rfc8032-test-validator").expect("bounded fixture ID"),
            ConsensusPublicKey::new(public_key),
            VotingPower::new(1).expect("positive fixture power"),
        )
        .expect("shape-valid fixture validator")
    }

    fn validator_set(public_keys: &[[u8; 32]]) -> ValidatorSet {
        let validators = public_keys
            .iter()
            .enumerate()
            .map(|(index, public_key)| {
                Validator::new(
                    ValidatorId::new([(index + 1) as u8; 32]),
                    ConsensusPublicKey::new(*public_key),
                    VotingPower::new(1).expect("positive fixture power"),
                )
                .expect("shape-valid fixture validator")
            })
            .collect();
        ValidatorSet::new(
            GenesisHash::new([0xA5; 32]),
            ChainId::from_static("trnm-crypto-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            ConsensusParametersHash::new([0x5A; 32]),
            validators,
        )
        .expect("shape-valid fixture validator set")
    }

    #[test]
    fn rfc8032_seed_signs_the_protocol_vote_root() {
        let signing_key = SigningKey::from_bytes(&RFC8032_TEST_1_SEED);
        let public_key = signing_key.verifying_key().to_bytes();
        let signature = signing_key.sign(&VOTE_ROOT).to_bytes();

        assert_eq!(public_key, EXPECTED_PUBLIC_KEY);
        assert_eq!(signature, EXPECTED_SIGNATURE);

        let verifier = StrictEd25519Verifier;
        assert!(verifier.verify(
            &validator(public_key),
            &SigningRoot::new(VOTE_ROOT),
            &SignatureBytes::from_array(signature),
        ));
    }

    #[test]
    fn wrong_root_mutated_signature_and_invalid_keys_fail_closed() {
        let verifier = StrictEd25519Verifier;

        assert!(!verifier.verify(
            &validator(EXPECTED_PUBLIC_KEY),
            &SigningRoot::new(WRONG_ROOT),
            &SignatureBytes::from_array(EXPECTED_SIGNATURE),
        ));

        assert!(!verifier.verify(
            &validator(EXPECTED_PUBLIC_KEY),
            &SigningRoot::new(VOTE_ROOT),
            &SignatureBytes::from_array(MUTATED_SIGNATURE),
        ));

        assert!(VerifyingKey::from_bytes(&UNDECODABLE_PUBLIC_KEY).is_err());
        assert!(!verifier.verify(
            &validator(UNDECODABLE_PUBLIC_KEY),
            &SigningRoot::new(VOTE_ROOT),
            &SignatureBytes::from_array(EXPECTED_SIGNATURE),
        ));

        // The identity encoding decompresses, but strict verification must
        // reject its small-order point rather than accepting a weak key.
        assert!(VerifyingKey::from_bytes(&SMALL_ORDER_PUBLIC_KEY).is_ok());
        assert!(!verifier.verify(
            &validator(SMALL_ORDER_PUBLIC_KEY),
            &SigningRoot::new(VOTE_ROOT),
            &SignatureBytes::from_array(EXPECTED_SIGNATURE),
        ));
    }

    #[test]
    fn strict_validator_set_admission_checks_every_key_before_activation() {
        let valid_set = validator_set(&[EXPECTED_PUBLIC_KEY]);
        assert!(validate_validator_set_strict_ed25519_v0(&valid_set).is_ok());
        let admitted = StrictValidatorSetV0::new(valid_set.clone()).expect("strict set admission");
        assert_eq!(admitted.validator_set(), &valid_set);
        assert_eq!(
            StrictEd25519Verifier
                .admit_validator_set_v0(valid_set.clone())
                .expect("strict verifier admission")
                .validator_set(),
            &valid_set
        );

        let undecodable = validator_set(&[EXPECTED_PUBLIC_KEY, UNDECODABLE_PUBLIC_KEY]);
        assert!(matches!(
            validate_validator_set_strict_ed25519_v0(&undecodable),
            Err(trnm_consensus_types::ValidationError::InvalidValidatorSet(
                "consensus public key is not a decodable Ed25519 compressed point"
            ))
        ));
        assert!(StrictValidatorSetV0::new(undecodable).is_err());

        let weak = validator_set(&[EXPECTED_PUBLIC_KEY, SMALL_ORDER_PUBLIC_KEY]);
        assert!(matches!(
            validate_validator_set_strict_ed25519_v0(&weak),
            Err(trnm_consensus_types::ValidationError::InvalidValidatorSet(
                "consensus public key is a weak/small-order Ed25519 point"
            ))
        ));
    }

    #[test]
    fn strict_public_key_admission_rejects_zero_and_weak_points() {
        assert!(
            validate_consensus_public_key_strict_ed25519_v0(&ConsensusPublicKey::new(
                EXPECTED_PUBLIC_KEY
            ))
            .is_ok()
        );
        assert!(
            validate_consensus_public_key_strict_ed25519_v0(&ConsensusPublicKey::new(
                UNDECODABLE_PUBLIC_KEY
            ))
            .is_err()
        );
        assert!(
            validate_consensus_public_key_strict_ed25519_v0(&ConsensusPublicKey::new(
                SMALL_ORDER_PUBLIC_KEY
            ))
            .is_err()
        );
    }

    #[test]
    fn strict_admission_source_contract_is_explicit() {
        let source = include_str!("lib.rs");
        let activation_source = include_str!("epoch_transition.rs");
        for required in [
            "pub struct StrictValidatorSetV0",
            "validate_validator_set_strict_ed25519_v0",
            "VerifyingKey::from_bytes",
            "verifying_key.is_weak()",
            "admit_validator_set_v0",
        ] {
            assert!(
                source.contains(required),
                "missing strict admission token: {required}"
            );
        }
        for required in [
            "validate_validator_set_strict_ed25519_v0(old_validator_set)",
            "validate_validator_set_strict_ed25519_v0(new_validator_set)",
            "JointHandoffKernelError::invalid_old_context()",
            "SameVersionEpochTransitionKernelError::invalid_new_epoch_finality()",
        ] {
            assert!(
                activation_source.contains(required),
                "strict activation lost admission preflight: {required}"
            );
        }
    }
}
