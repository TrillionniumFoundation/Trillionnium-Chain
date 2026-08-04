#![no_std]
#![forbid(unsafe_code)]
//! Strict, verification-only cryptographic boundary for PoCO-BFT v0.
//!
//! This crate deliberately exposes no signing or private-key API. Consensus
//! messages are verified as RFC 8032 Ed25519 signatures over the exact raw
//! 32-byte [`trnm_consensus_types::SigningRoot`].

use ed25519_dalek::{Signature, VerifyingKey};
use trnm_consensus_types::{SignatureBytes, SignatureVerifier, SigningRoot, Validator};

/// Stateless strict Ed25519 verifier for PoCO-BFT v0 consensus roots.
///
/// Public keys must decode as Ed25519 compressed points. `verify_strict`
/// additionally rejects non-canonical signature scalars/R encodings and
/// small-order public-key/signature points. Any decode or verification error
/// fails closed.
#[derive(Debug, Clone, Copy, Default)]
pub struct StrictEd25519Verifier;

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
        ConsensusPublicKey, SignatureBytes, SignatureVerifier, SigningRoot, Validator, ValidatorId,
        VotingPower,
    };

    use super::StrictEd25519Verifier;

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
}
