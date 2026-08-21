//! Exact public key-role bindings for the PoCO laboratory validator.
//!
//! These records are consumed by the live P2P transport. They are public
//! configuration facts, not signer capabilities: no private key, generic
//! signing API, credential, lease, or production activation is present.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use trnm_consensus_types::{ValidatorId, ValidatorSet};

const KEY_ROLE_BINDING_MAGIC_V1: [u8; 8] = *b"TRNMKRB1";
const KEY_ROLE_BINDING_CHECKSUM_DOMAIN_V1: &[u8] = b"trnm.poco-g3.validator-key-role-binding.v1";
const KEY_ROLE_REGISTRY_DIGEST_DOMAIN_V1: &[u8] = b"trnm.poco-g3.validator-key-role-registry.v1";

pub const VALIDATOR_KEY_ROLE_BINDING_SCHEMA_V1: u16 = 1;
pub const VALIDATOR_KEY_ROLE_BINDING_BYTES_V1: usize = 8 + 2 + 32 * 4 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorKeyRoleBindingV1 {
    validator_id: ValidatorId,
    consensus_public_key: [u8; 32],
    p2p_identity_public_key: [u8; 32],
    operator_recovery_public_key: [u8; 32],
    checksum: [u8; 32],
}

impl ValidatorKeyRoleBindingV1 {
    pub fn new(
        validator_id: ValidatorId,
        consensus_public_key: [u8; 32],
        p2p_identity_public_key: [u8; 32],
        operator_recovery_public_key: [u8; 32],
    ) -> Result<Self, ValidatorKeyRoleErrorV1> {
        for key in [
            consensus_public_key,
            p2p_identity_public_key,
            operator_recovery_public_key,
        ] {
            let parsed = VerifyingKey::from_bytes(&key)
                .map_err(|_| ValidatorKeyRoleErrorV1::InvalidEd25519Key)?;
            if parsed.is_weak() {
                return Err(ValidatorKeyRoleErrorV1::WeakEd25519Key);
            }
        }
        if consensus_public_key == p2p_identity_public_key
            || consensus_public_key == operator_recovery_public_key
            || p2p_identity_public_key == operator_recovery_public_key
        {
            return Err(ValidatorKeyRoleErrorV1::RoleKeyReuse);
        }
        let checksum = binding_checksum_v1(
            validator_id,
            consensus_public_key,
            p2p_identity_public_key,
            operator_recovery_public_key,
        );
        Ok(Self {
            validator_id,
            consensus_public_key,
            p2p_identity_public_key,
            operator_recovery_public_key,
            checksum,
        })
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, ValidatorKeyRoleErrorV1> {
        if bytes.len() != VALIDATOR_KEY_ROLE_BINDING_BYTES_V1 {
            return Err(ValidatorKeyRoleErrorV1::WrongLength);
        }
        if bytes[..8] != KEY_ROLE_BINDING_MAGIC_V1 {
            return Err(ValidatorKeyRoleErrorV1::WrongMagic);
        }
        if u16::from_be_bytes(bytes[8..10].try_into().expect("exact schema bytes"))
            != VALIDATOR_KEY_ROLE_BINDING_SCHEMA_V1
        {
            return Err(ValidatorKeyRoleErrorV1::WrongSchema);
        }
        let value = Self::new(
            ValidatorId::new(bytes[10..42].try_into().expect("exact validator ID bytes")),
            bytes[42..74].try_into().expect("exact consensus key bytes"),
            bytes[74..106].try_into().expect("exact P2P key bytes"),
            bytes[106..138]
                .try_into()
                .expect("exact operator/recovery key bytes"),
        )?;
        if bytes[138..170] != value.checksum {
            return Err(ValidatorKeyRoleErrorV1::ChecksumMismatch);
        }
        Ok(value)
    }

    pub fn encode_exact(self) -> [u8; VALIDATOR_KEY_ROLE_BINDING_BYTES_V1] {
        let mut output = [0; VALIDATOR_KEY_ROLE_BINDING_BYTES_V1];
        output[..8].copy_from_slice(&KEY_ROLE_BINDING_MAGIC_V1);
        output[8..10].copy_from_slice(&VALIDATOR_KEY_ROLE_BINDING_SCHEMA_V1.to_be_bytes());
        output[10..42].copy_from_slice(self.validator_id.as_bytes());
        output[42..74].copy_from_slice(&self.consensus_public_key);
        output[74..106].copy_from_slice(&self.p2p_identity_public_key);
        output[106..138].copy_from_slice(&self.operator_recovery_public_key);
        output[138..170].copy_from_slice(&self.checksum);
        output
    }

    pub const fn validator_id(self) -> ValidatorId {
        self.validator_id
    }

    pub const fn consensus_public_key(self) -> [u8; 32] {
        self.consensus_public_key
    }

    pub const fn p2p_identity_public_key(self) -> [u8; 32] {
        self.p2p_identity_public_key
    }

    pub const fn operator_recovery_public_key(self) -> [u8; 32] {
        self.operator_recovery_public_key
    }

    pub const fn checksum(self) -> [u8; 32] {
        self.checksum
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorKeyRoleRegistryV1 {
    bindings: BTreeMap<ValidatorId, ValidatorKeyRoleBindingV1>,
    digest: [u8; 32],
}

impl ValidatorKeyRoleRegistryV1 {
    pub fn new(
        validator_set: &ValidatorSet,
        bindings: Vec<ValidatorKeyRoleBindingV1>,
    ) -> Result<Self, ValidatorKeyRoleErrorV1> {
        if bindings.len() != validator_set.validators().len() {
            return Err(ValidatorKeyRoleErrorV1::ValidatorInventoryMismatch);
        }
        let mut by_id = BTreeMap::new();
        let mut all_role_keys = BTreeSet::new();
        for binding in bindings {
            let validator = validator_set
                .validator(binding.validator_id())
                .ok_or(ValidatorKeyRoleErrorV1::ValidatorInventoryMismatch)?;
            if validator.consensus_key().as_bytes() != &binding.consensus_public_key() {
                return Err(ValidatorKeyRoleErrorV1::ConsensusBindingMismatch);
            }
            for key in [
                binding.consensus_public_key(),
                binding.p2p_identity_public_key(),
                binding.operator_recovery_public_key(),
            ] {
                if !all_role_keys.insert(key) {
                    return Err(ValidatorKeyRoleErrorV1::RoleKeyReuse);
                }
            }
            if by_id.insert(binding.validator_id(), binding).is_some() {
                return Err(ValidatorKeyRoleErrorV1::DuplicateValidator);
            }
        }
        if validator_set
            .validators()
            .iter()
            .any(|validator| !by_id.contains_key(&validator.id()))
        {
            return Err(ValidatorKeyRoleErrorV1::ValidatorInventoryMismatch);
        }
        let digest = registry_digest_v1(by_id.values().copied());
        Ok(Self {
            bindings: by_id,
            digest,
        })
    }

    pub fn binding(&self, validator_id: ValidatorId) -> Option<ValidatorKeyRoleBindingV1> {
        self.bindings.get(&validator_id).copied()
    }

    pub fn p2p_identity_public_key(&self, validator_id: ValidatorId) -> Option<[u8; 32]> {
        self.binding(validator_id)
            .map(ValidatorKeyRoleBindingV1::p2p_identity_public_key)
    }

    pub fn operator_recovery_public_key(&self, validator_id: ValidatorId) -> Option<[u8; 32]> {
        self.binding(validator_id)
            .map(ValidatorKeyRoleBindingV1::operator_recovery_public_key)
    }

    pub const fn digest_v1(&self) -> [u8; 32] {
        self.digest
    }

    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorKeyRoleErrorV1 {
    WrongLength,
    WrongMagic,
    WrongSchema,
    InvalidEd25519Key,
    WeakEd25519Key,
    RoleKeyReuse,
    ChecksumMismatch,
    DuplicateValidator,
    ValidatorInventoryMismatch,
    ConsensusBindingMismatch,
}

impl fmt::Display for ValidatorKeyRoleErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::WrongLength => "validator key-role binding has the wrong length",
            Self::WrongMagic => "validator key-role binding has the wrong magic",
            Self::WrongSchema => "validator key-role binding has the wrong schema",
            Self::InvalidEd25519Key => "validator key-role binding contains a non-Ed25519 key",
            Self::WeakEd25519Key => "validator key-role binding contains a weak Ed25519 key",
            Self::RoleKeyReuse => "validator key-role registry reuses a public key",
            Self::ChecksumMismatch => "validator key-role binding checksum differs",
            Self::DuplicateValidator => "validator key-role registry repeats a validator",
            Self::ValidatorInventoryMismatch => {
                "validator key-role registry differs from the validator set"
            }
            Self::ConsensusBindingMismatch => {
                "validator key-role consensus key differs from the validator set"
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ValidatorKeyRoleErrorV1 {}

fn binding_checksum_v1(
    validator_id: ValidatorId,
    consensus_public_key: [u8; 32],
    p2p_identity_public_key: [u8; 32],
    operator_recovery_public_key: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ROLE_BINDING_CHECKSUM_DOMAIN_V1);
    hasher.update(KEY_ROLE_BINDING_MAGIC_V1);
    hasher.update(VALIDATOR_KEY_ROLE_BINDING_SCHEMA_V1.to_be_bytes());
    hasher.update(validator_id.as_bytes());
    hasher.update(consensus_public_key);
    hasher.update(p2p_identity_public_key);
    hasher.update(operator_recovery_public_key);
    hasher.finalize().into()
}

fn registry_digest_v1(
    bindings: impl ExactSizeIterator<Item = ValidatorKeyRoleBindingV1>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_ROLE_REGISTRY_DIGEST_DOMAIN_V1);
    hasher.update(VALIDATOR_KEY_ROLE_BINDING_SCHEMA_V1.to_be_bytes());
    hasher.update((bindings.len() as u64).to_be_bytes());
    for binding in bindings {
        hasher.update(binding.encode_exact());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersV0, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    use super::*;

    fn fixture() -> (
        ValidatorSet,
        Vec<ValidatorKeyRoleBindingV1>,
        Vec<[SigningKey; 3]>,
    ) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let keys = (0..4)
            .map(|index| {
                [
                    SigningKey::from_bytes(&[0x21 + index; 32]),
                    SigningKey::from_bytes(&[0x41 + index; 32]),
                    SigningKey::from_bytes(&[0x61 + index; 32]),
                ]
            })
            .collect::<Vec<_>>();
        let validators = keys
            .iter()
            .enumerate()
            .map(|(index, role_keys)| {
                Validator::new(
                    ValidatorId::new([0x11 + u8::try_from(index).unwrap(); 32]),
                    ConsensusPublicKey::new(role_keys[0].verifying_key().to_bytes()),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let set = ValidatorSet::new(
            GenesisHash::new([0x22; 32]),
            ChainId::new("trnm-poco-g3-lab-v0").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap();
        let bindings = set
            .validators()
            .iter()
            .zip(&keys)
            .map(|(validator, role_keys)| {
                ValidatorKeyRoleBindingV1::new(
                    validator.id(),
                    role_keys[0].verifying_key().to_bytes(),
                    role_keys[1].verifying_key().to_bytes(),
                    role_keys[2].verifying_key().to_bytes(),
                )
                .unwrap()
            })
            .collect();
        (set, bindings, keys)
    }

    #[test]
    fn exact_schema_vector_roundtrips_and_mutation_fails_closed() {
        let (_, bindings, _) = fixture();
        let binding = bindings[0];
        let encoded = binding.encode_exact();
        assert_eq!(&encoded[..8], b"TRNMKRB1");
        assert_eq!(&encoded[8..10], &1u16.to_be_bytes());
        assert_eq!(encoded.len(), VALIDATOR_KEY_ROLE_BINDING_BYTES_V1);
        assert_eq!(
            ValidatorKeyRoleBindingV1::decode_exact(&encoded).unwrap(),
            binding
        );
        let mut mutated = encoded;
        mutated[90] ^= 1;
        assert_eq!(
            ValidatorKeyRoleBindingV1::decode_exact(&mutated),
            Err(ValidatorKeyRoleErrorV1::ChecksumMismatch)
        );
    }

    #[test]
    fn equal_role_keys_and_role_substitution_are_rejected() {
        let (set, bindings, keys) = fixture();
        assert_eq!(
            ValidatorKeyRoleBindingV1::new(
                set.validators()[0].id(),
                keys[0][0].verifying_key().to_bytes(),
                keys[0][0].verifying_key().to_bytes(),
                keys[0][2].verifying_key().to_bytes(),
            ),
            Err(ValidatorKeyRoleErrorV1::RoleKeyReuse)
        );
        let mut substituted = bindings;
        substituted[1] = ValidatorKeyRoleBindingV1::new(
            substituted[1].validator_id(),
            substituted[1].consensus_public_key(),
            substituted[0].p2p_identity_public_key(),
            substituted[1].operator_recovery_public_key(),
        )
        .unwrap();
        assert!(matches!(
            ValidatorKeyRoleRegistryV1::new(&set, substituted),
            Err(ValidatorKeyRoleErrorV1::RoleKeyReuse)
        ));
    }

    #[test]
    fn registry_reopen_is_deterministic_and_rekey_changes_its_digest() {
        let (set, bindings, keys) = fixture();
        let first = ValidatorKeyRoleRegistryV1::new(&set, bindings.clone()).unwrap();
        let reopened = ValidatorKeyRoleRegistryV1::new(&set, bindings.clone()).unwrap();
        assert_eq!(first.digest_v1(), reopened.digest_v1());

        let mut rekeyed = bindings;
        rekeyed[0] = ValidatorKeyRoleBindingV1::new(
            rekeyed[0].validator_id(),
            rekeyed[0].consensus_public_key(),
            SigningKey::from_bytes(&[0x7f; 32])
                .verifying_key()
                .to_bytes(),
            keys[0][2].verifying_key().to_bytes(),
        )
        .unwrap();
        let rekeyed = ValidatorKeyRoleRegistryV1::new(&set, rekeyed).unwrap();
        assert_ne!(first.digest_v1(), rekeyed.digest_v1());
    }
}
