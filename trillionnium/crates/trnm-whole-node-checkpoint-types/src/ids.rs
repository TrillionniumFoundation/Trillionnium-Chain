use core::{fmt, num::NonZeroU64};

use sha2::{Digest, Sha256};

/// Maximum input accepted by the scope descriptor constructor.
pub const MAX_WHOLE_NODE_PUBLIC_DESCRIPTOR_BYTES_V1: usize = 1024;

const SCOPE_DOMAIN_V1: &[u8] = b"trnm.whole-node-checkpoint.scope.v1\0";

/// Closed failures for primitive checkpoint data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WholeNodeCheckpointTypeErrorV1 {
    EmptyPublicDescriptor,
    PublicDescriptorTooLarge,
    ZeroScope,
    ZeroCutDigest,
    ZeroCheckpointChecksum,
    ZeroProcessGeneration,
    ZeroApplicationValidationGeneration,
    GenerationOverflow,
}

impl fmt::Display for WholeNodeCheckpointTypeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyPublicDescriptor => "whole-node public descriptor is empty",
            Self::PublicDescriptorTooLarge => "whole-node public descriptor exceeds its bound",
            Self::ZeroScope => "whole-node checkpoint scope is zero",
            Self::ZeroCutDigest => "whole-node cut digest is zero",
            Self::ZeroCheckpointChecksum => "whole-node checkpoint checksum is zero",
            Self::ZeroProcessGeneration => "process generation is zero",
            Self::ZeroApplicationValidationGeneration => {
                "application validation generation is zero"
            }
            Self::GenerationOverflow => "whole-node checkpoint generation overflow",
        };
        formatter.write_str(message)
    }
}

/// Domain-separated public namespace for one checkpoint lineage.
///
/// Deriving a scope does not create a store, lease, or anti-rollback domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WholeNodeCheckpointScopeV1([u8; 32]);

impl WholeNodeCheckpointScopeV1 {
    pub fn from_public_descriptor(
        descriptor: &[u8],
    ) -> Result<Self, WholeNodeCheckpointTypeErrorV1> {
        if descriptor.is_empty() {
            return Err(WholeNodeCheckpointTypeErrorV1::EmptyPublicDescriptor);
        }
        if descriptor.len() > MAX_WHOLE_NODE_PUBLIC_DESCRIPTOR_BYTES_V1 {
            return Err(WholeNodeCheckpointTypeErrorV1::PublicDescriptorTooLarge);
        }
        let mut hash = Sha256::new();
        hash.update(SCOPE_DOMAIN_V1);
        hash.update((descriptor.len() as u32).to_be_bytes());
        hash.update(descriptor);
        Self::from_exact_bytes(hash.finalize().into())
    }

    pub fn from_exact_bytes(bytes: [u8; 32]) -> Result<Self, WholeNodeCheckpointTypeErrorV1> {
        if bytes == [0; 32] {
            return Err(WholeNodeCheckpointTypeErrorV1::ZeroScope);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Non-zero digest occupying one named position in a cumulative cut.
///
/// The semantic taxonomy comes from the private field that contains this
/// value; this wrapper deliberately carries no authority of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WholeNodeCutDigestV1([u8; 32]);

impl WholeNodeCutDigestV1 {
    pub fn from_exact_bytes(bytes: [u8; 32]) -> Result<Self, WholeNodeCheckpointTypeErrorV1> {
        if bytes == [0; 32] {
            return Err(WholeNodeCheckpointTypeErrorV1::ZeroCutDigest);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Monotonic generation of the cumulative checkpoint record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WholeNodeCheckpointGenerationV1(u64);

impl WholeNodeCheckpointGenerationV1 {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn checked_next(self) -> Result<Self, WholeNodeCheckpointTypeErrorV1> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(WholeNodeCheckpointTypeErrorV1::GenerationOverflow)
    }
}

/// Non-zero generation of one process fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessGenerationV1(NonZeroU64);

impl ProcessGenerationV1 {
    pub fn new(value: u64) -> Result<Self, WholeNodeCheckpointTypeErrorV1> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(WholeNodeCheckpointTypeErrorV1::ZeroProcessGeneration)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Non-zero generation of an application-validation artifact lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApplicationValidationGenerationV1(NonZeroU64);

impl ApplicationValidationGenerationV1 {
    pub fn new(value: u64) -> Result<Self, WholeNodeCheckpointTypeErrorV1> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(WholeNodeCheckpointTypeErrorV1::ZeroApplicationValidationGeneration)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Domain-separated checksum of one complete canonical checkpoint prefix.
///
/// This is public comparison data, not proof that a checkpoint was persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WholeNodeCheckpointChecksumV1([u8; 32]);

impl WholeNodeCheckpointChecksumV1 {
    pub fn from_exact_bytes(bytes: [u8; 32]) -> Result<Self, WholeNodeCheckpointTypeErrorV1> {
        if bytes == [0; 32] {
            return Err(WholeNodeCheckpointTypeErrorV1::ZeroCheckpointChecksum);
        }
        Ok(Self(bytes))
    }

    pub(crate) const fn from_digest(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
