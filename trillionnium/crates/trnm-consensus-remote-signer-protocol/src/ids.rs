use core::{fmt, num::NonZeroU64};

use sha2::{Digest, Sha256};

pub const MAX_REMOTE_SIGNER_PUBLIC_DESCRIPTOR_BYTES_V1: usize = 1024;

const ROLE_PROFILE_DOMAIN_V1: &[u8] = b"trnm.remote-signer.protocol.role-profile-ref.v1\0";
const SERVICE_PROFILE_DOMAIN_V1: &[u8] = b"trnm.remote-signer.protocol.service-profile-ref.v1\0";
const CLIENT_PROFILE_DOMAIN_V1: &[u8] = b"trnm.remote-signer.protocol.client-profile-ref.v1\0";
const LEASE_ID_DOMAIN_V1: &[u8] = b"trnm.remote-signer.protocol.lease-id.v1\0";
const REQUEST_NONCE_DOMAIN_V1: &[u8] = b"trnm.remote-signer.protocol.request-nonce.v1\0";
const CHECKPOINT_WITNESS_DOMAIN_V1: &[u8] =
    b"trnm.remote-signer.protocol.whole-node-checkpoint-witness.v1\0";
const PURPOSE_PROFILE_DOMAIN_V1: &[u8] =
    b"trnm.remote-signer.protocol.vote-timeout-purpose-profile.v1\0";

const CONSENSUS_ROLE_TAG_V1: u8 = 1;
const VOTE_PURPOSE_TAG_V1: u8 = 0;
const TIMEOUT_VOTE_PURPOSE_TAG_V1: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSignerIdErrorV1 {
    EmptyPublicDescriptor,
    PublicDescriptorTooLarge,
    ZeroReference,
    ZeroProcessGeneration,
    ZeroCheckpointGeneration,
    ZeroCheckpointChecksum,
    CheckpointWitnessDigestMismatch,
}

impl fmt::Display for RemoteSignerIdErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPublicDescriptor => {
                formatter.write_str("remote signer public descriptor is empty")
            }
            Self::PublicDescriptorTooLarge => {
                formatter.write_str("remote signer public descriptor exceeds its bound")
            }
            Self::ZeroReference => formatter.write_str("remote signer reference is zero"),
            Self::ZeroProcessGeneration => {
                formatter.write_str("remote signer process generation is zero")
            }
            Self::ZeroCheckpointGeneration => {
                formatter.write_str("whole-node checkpoint generation is zero")
            }
            Self::ZeroCheckpointChecksum => {
                formatter.write_str("whole-node checkpoint checksum is zero")
            }
            Self::CheckpointWitnessDigestMismatch => {
                formatter.write_str("whole-node checkpoint witness digest differs")
            }
        }
    }
}

macro_rules! public_profile_ref {
    ($name:ident, $domain:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn from_public_descriptor(
                descriptor: &[u8],
            ) -> Result<Self, RemoteSignerIdErrorV1> {
                Ok(Self(digest_bounded_public_descriptor_v1(
                    $domain, descriptor,
                )?))
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub(crate) fn from_exact_bytes(bytes: [u8; 32]) -> Result<Self, RemoteSignerIdErrorV1> {
                require_nonzero_reference_v1(bytes)?;
                Ok(Self(bytes))
            }
        }
    };
}

public_profile_ref!(
    RemoteSignerRoleProfileRefV1,
    ROLE_PROFILE_DOMAIN_V1,
    "Public reference to the configured consensus-role profile."
);

public_profile_ref!(
    RemoteSignerServiceProfileRefV1,
    SERVICE_PROFILE_DOMAIN_V1,
    "Public reference to one signer-service profile."
);

public_profile_ref!(
    RemoteSignerClientProfileRefV1,
    CLIENT_PROFILE_DOMAIN_V1,
    "Public reference to one node-side client profile."
);

/// Non-zero process generation selected by a future external generation CAS.
///
/// This value is data only. Calling `new` does not allocate, transfer, or
/// activate a process generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessGenerationV1(NonZeroU64);

impl ProcessGenerationV1 {
    pub fn new(value: u64) -> Result<Self, RemoteSignerIdErrorV1> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(RemoteSignerIdErrorV1::ZeroProcessGeneration)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Domain-separated public identifier for a future externally granted lease.
///
/// The constructor only derives protocol data; it grants no signer authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteSignerLeaseIdV1([u8; 32]);

impl RemoteSignerLeaseIdV1 {
    pub fn from_public_grant_descriptor(descriptor: &[u8]) -> Result<Self, RemoteSignerIdErrorV1> {
        Ok(Self(digest_bounded_public_descriptor_v1(
            LEASE_ID_DOMAIN_V1,
            descriptor,
        )?))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn from_exact_bytes(bytes: [u8; 32]) -> Result<Self, RemoteSignerIdErrorV1> {
        require_nonzero_reference_v1(bytes)?;
        Ok(Self(bytes))
    }
}

/// Domain-separated, bounded request nonce data.
///
/// Derivation is deterministic. This type does not establish uniqueness,
/// freshness, replay protection, or durable nonce admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteSignerRequestNonceV1([u8; 32]);

impl RemoteSignerRequestNonceV1 {
    pub fn from_public_nonce_material(material: &[u8]) -> Result<Self, RemoteSignerIdErrorV1> {
        Ok(Self(digest_bounded_public_descriptor_v1(
            REQUEST_NONCE_DOMAIN_V1,
            material,
        )?))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn from_exact_bytes(bytes: [u8; 32]) -> Result<Self, RemoteSignerIdErrorV1> {
        require_nonzero_reference_v1(bytes)?;
        Ok(Self(bytes))
    }
}

/// Exact public witness for one non-zero whole-node checkpoint generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteSignerCheckpointWitnessV1 {
    generation: NonZeroU64,
    checkpoint_checksum: [u8; 32],
    witness_digest: [u8; 32],
}

impl RemoteSignerCheckpointWitnessV1 {
    pub fn new(
        generation: u64,
        checkpoint_checksum: [u8; 32],
    ) -> Result<Self, RemoteSignerIdErrorV1> {
        let generation =
            NonZeroU64::new(generation).ok_or(RemoteSignerIdErrorV1::ZeroCheckpointGeneration)?;
        if checkpoint_checksum == [0; 32] {
            return Err(RemoteSignerIdErrorV1::ZeroCheckpointChecksum);
        }
        let witness_digest = checkpoint_witness_digest_v1(generation.get(), checkpoint_checksum);
        Ok(Self {
            generation,
            checkpoint_checksum,
            witness_digest,
        })
    }

    pub const fn generation(self) -> u64 {
        self.generation.get()
    }

    pub const fn checkpoint_checksum(self) -> [u8; 32] {
        self.checkpoint_checksum
    }

    pub const fn witness_digest(self) -> [u8; 32] {
        self.witness_digest
    }

    pub(crate) fn from_exact_parts(
        generation: u64,
        checkpoint_checksum: [u8; 32],
        supplied_witness_digest: [u8; 32],
    ) -> Result<Self, RemoteSignerIdErrorV1> {
        let value = Self::new(generation, checkpoint_checksum)?;
        if value.witness_digest != supplied_witness_digest {
            return Err(RemoteSignerIdErrorV1::CheckpointWitnessDigestMismatch);
        }
        Ok(value)
    }
}

/// Frozen digest of the only purposes accepted by protocol schema 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteSignerPurposeProfileDigestV1([u8; 32]);

impl RemoteSignerPurposeProfileDigestV1 {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn from_exact_bytes(bytes: [u8; 32]) -> Result<Self, RemoteSignerIdErrorV1> {
        require_nonzero_reference_v1(bytes)?;
        Ok(Self(bytes))
    }
}

pub fn vote_timeout_purpose_profile_digest_v1() -> RemoteSignerPurposeProfileDigestV1 {
    let mut hash = Sha256::new();
    hash.update(PURPOSE_PROFILE_DOMAIN_V1);
    hash.update(1u16.to_be_bytes());
    hash.update([CONSENSUS_ROLE_TAG_V1]);
    hash.update(2u16.to_be_bytes());
    hash.update([VOTE_PURPOSE_TAG_V1, TIMEOUT_VOTE_PURPOSE_TAG_V1]);
    RemoteSignerPurposeProfileDigestV1(hash.finalize().into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteSignerRequestFingerprintV1([u8; 32]);

impl RemoteSignerRequestFingerprintV1 {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn from_exact_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteSignerResponseFingerprintV1([u8; 32]);

impl RemoteSignerResponseFingerprintV1 {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn from_exact_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

fn digest_bounded_public_descriptor_v1(
    domain: &[u8],
    descriptor: &[u8],
) -> Result<[u8; 32], RemoteSignerIdErrorV1> {
    if descriptor.is_empty() {
        return Err(RemoteSignerIdErrorV1::EmptyPublicDescriptor);
    }
    if descriptor.len() > MAX_REMOTE_SIGNER_PUBLIC_DESCRIPTOR_BYTES_V1 {
        return Err(RemoteSignerIdErrorV1::PublicDescriptorTooLarge);
    }
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(
        u32::try_from(descriptor.len())
            .expect("bounded descriptor length fits u32")
            .to_be_bytes(),
    );
    hash.update(descriptor);
    let digest = hash.finalize().into();
    require_nonzero_reference_v1(digest)?;
    Ok(digest)
}

fn require_nonzero_reference_v1(bytes: [u8; 32]) -> Result<(), RemoteSignerIdErrorV1> {
    if bytes == [0; 32] {
        return Err(RemoteSignerIdErrorV1::ZeroReference);
    }
    Ok(())
}

fn checkpoint_witness_digest_v1(generation: u64, checkpoint_checksum: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CHECKPOINT_WITNESS_DOMAIN_V1);
    hash.update(generation.to_be_bytes());
    hash.update(checkpoint_checksum);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PURPOSE_PROFILE_DIGEST_GOLDEN_V1: [u8; 32] = [
        0x56, 0x11, 0xbc, 0xe3, 0xe7, 0x3e, 0x29, 0x4a, 0xa4, 0xfe, 0xce, 0xf8, 0x42, 0xf6, 0xbe,
        0xcd, 0x05, 0x1e, 0x53, 0xc2, 0xbb, 0x62, 0x00, 0x13, 0xf8, 0x4a, 0x9a, 0x17, 0x25, 0xe8,
        0x3e, 0xf4,
    ];
    const CHECKPOINT_WITNESS_DIGEST_GOLDEN_V1: [u8; 32] = [
        0x32, 0x07, 0xd7, 0xe5, 0x90, 0xaf, 0xdf, 0x4a, 0x07, 0x11, 0xe1, 0xa2, 0x9d, 0xd1, 0x2f,
        0xb9, 0x1c, 0x10, 0xd5, 0x49, 0xed, 0x73, 0x90, 0xc1, 0xcc, 0x49, 0xa2, 0x87, 0x89, 0x44,
        0x5b, 0x05,
    ];

    #[test]
    fn public_reference_domains_are_distinct_and_bounded() {
        let descriptor = b"same-public-descriptor";
        let role = RemoteSignerRoleProfileRefV1::from_public_descriptor(descriptor).unwrap();
        let service = RemoteSignerServiceProfileRefV1::from_public_descriptor(descriptor).unwrap();
        let client = RemoteSignerClientProfileRefV1::from_public_descriptor(descriptor).unwrap();
        let lease = RemoteSignerLeaseIdV1::from_public_grant_descriptor(descriptor).unwrap();
        let nonce = RemoteSignerRequestNonceV1::from_public_nonce_material(descriptor).unwrap();

        let values = [
            *role.as_bytes(),
            *service.as_bytes(),
            *client.as_bytes(),
            *lease.as_bytes(),
            *nonce.as_bytes(),
        ];
        for (index, value) in values.iter().enumerate() {
            assert_ne!(*value, [0; 32]);
            for other in &values[index + 1..] {
                assert_ne!(value, other);
            }
        }

        assert_eq!(
            RemoteSignerRoleProfileRefV1::from_public_descriptor(&[]),
            Err(RemoteSignerIdErrorV1::EmptyPublicDescriptor)
        );
        assert_eq!(
            RemoteSignerRoleProfileRefV1::from_public_descriptor(
                &alloc::vec![0; MAX_REMOTE_SIGNER_PUBLIC_DESCRIPTOR_BYTES_V1 + 1]
            ),
            Err(RemoteSignerIdErrorV1::PublicDescriptorTooLarge)
        );
    }

    #[test]
    fn generations_checkpoint_and_raw_reopen_fail_closed() {
        assert_eq!(
            ProcessGenerationV1::new(0),
            Err(RemoteSignerIdErrorV1::ZeroProcessGeneration)
        );
        assert_eq!(
            RemoteSignerCheckpointWitnessV1::new(0, [1; 32]),
            Err(RemoteSignerIdErrorV1::ZeroCheckpointGeneration)
        );
        assert_eq!(
            RemoteSignerCheckpointWitnessV1::new(1, [0; 32]),
            Err(RemoteSignerIdErrorV1::ZeroCheckpointChecksum)
        );

        let witness = RemoteSignerCheckpointWitnessV1::new(7, [8; 32]).unwrap();
        assert_eq!(witness.generation(), 7);
        assert_eq!(witness.checkpoint_checksum(), [8; 32]);
        assert_eq!(
            witness.witness_digest(),
            CHECKPOINT_WITNESS_DIGEST_GOLDEN_V1
        );
        assert_eq!(
            RemoteSignerCheckpointWitnessV1::from_exact_parts(7, [8; 32], [9; 32]),
            Err(RemoteSignerIdErrorV1::CheckpointWitnessDigestMismatch)
        );
        assert_eq!(
            RemoteSignerLeaseIdV1::from_exact_bytes([0; 32]),
            Err(RemoteSignerIdErrorV1::ZeroReference)
        );
    }

    #[test]
    fn purpose_profile_is_frozen_and_nonzero() {
        let first = vote_timeout_purpose_profile_digest_v1();
        assert_eq!(*first.as_bytes(), PURPOSE_PROFILE_DIGEST_GOLDEN_V1);
    }

    #[test]
    fn nonce_derivation_is_deterministic_data_not_freshness_authority() {
        let first = RemoteSignerRequestNonceV1::from_public_nonce_material(b"same-nonce").unwrap();
        let replay = RemoteSignerRequestNonceV1::from_public_nonce_material(b"same-nonce").unwrap();
        let other = RemoteSignerRequestNonceV1::from_public_nonce_material(b"other-nonce").unwrap();
        assert_eq!(first, replay);
        assert_ne!(first, other);
        assert!(!crate::REMOTE_SIGNER_PROTOCOL_NONCE_FRESHNESS_AUTHORITY_V1);
    }
}
