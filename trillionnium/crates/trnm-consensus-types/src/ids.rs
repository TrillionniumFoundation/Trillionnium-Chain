use alloc::vec::Vec;

use crate::{Result, ValidationError};

pub const MAX_CONSENSUS_STRING_BYTES: usize = 128;
pub const MAX_VALIDATOR_ID_BYTES: usize = 128;
pub const SIGNATURE_BYTES: usize = 64;

macro_rules! fixed_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const ZERO: Self = Self([0; 32]);

            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }

            pub fn is_zero(&self) -> bool {
                self.0 == [0; 32]
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self::new(bytes)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(value: $name) -> Self {
                value.into_bytes()
            }
        }
    };
}

fixed_id!(GenesisHash);
fixed_id!(BlockId);
fixed_id!(PayloadDigest);
fixed_id!(StateRoot);
fixed_id!(ReceiptsRoot);
fixed_id!(EvidenceRoot);
fixed_id!(EvidenceId);
fixed_id!(NextEpochCommitmentHash);
fixed_id!(UpgradePlanHash);
fixed_id!(ValidatorSetId);
fixed_id!(ConsensusParametersHash);
fixed_id!(ConsensusPublicKey);
fixed_id!(EpochTransitionId);
fixed_id!(CertificateId);
fixed_id!(SigningRoot);

/// A CEV0 `ConsensusString` stored inline so consensus state remains `Copy`
/// and does not depend on allocation after validation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConsensusString {
    length: u16,
    bytes: [u8; MAX_CONSENSUS_STRING_BYTES],
}

impl ConsensusString {
    pub fn new(value: &str) -> Result<Self> {
        Self::from_bytes(value.as_bytes())
    }

    pub fn from_bytes(value: &[u8]) -> Result<Self> {
        if !valid_consensus_string(value) {
            return Err(ValidationError::InvalidConsensusString);
        }
        let mut bytes = [0u8; MAX_CONSENSUS_STRING_BYTES];
        bytes[..value.len()].copy_from_slice(value);
        Ok(Self {
            length: value.len() as u16,
            bytes,
        })
    }

    /// Constructs a statically known consensus string and validates it during
    /// constant evaluation. Invalid literals fail the build.
    pub const fn from_static(value: &'static str) -> Self {
        let source = value.as_bytes();
        if source.is_empty() || source.len() > MAX_CONSENSUS_STRING_BYTES {
            panic!("invalid consensus string length");
        }
        let first = source[0];
        if !is_consensus_string_first(first) {
            panic!("invalid consensus string first byte");
        }
        let mut bytes = [0u8; MAX_CONSENSUS_STRING_BYTES];
        let mut index = 0usize;
        while index < source.len() {
            let byte = source[index];
            if index != 0 && !is_consensus_string_tail(byte) {
                panic!("invalid consensus string byte");
            }
            bytes[index] = byte;
            index += 1;
        }
        Self {
            length: source.len() as u16,
            bytes,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes())
            .expect("validated ConsensusString contains restricted ASCII")
    }
}

impl core::fmt::Debug for ConsensusString {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ConsensusString")
            .field(&self.as_str())
            .finish()
    }
}

impl Ord for ConsensusString {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl PartialOrd for ConsensusString {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub type ChainId = ConsensusString;

const fn is_consensus_string_first(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

const fn is_consensus_string_tail(byte: u8) -> bool {
    is_consensus_string_first(byte) || matches!(byte, b'.' | b'_' | b':' | b'-')
}

fn valid_consensus_string(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CONSENSUS_STRING_BYTES
        && is_consensus_string_first(value[0])
        && value[1..].iter().copied().all(is_consensus_string_tail)
}

/// Validator IDs are opaque CEV0 `Bytes`, bounded by the active v0 maximum.
/// The inline representation preserves deterministic ordering and `Copy`
/// semantics for the consensus core while hashing the original raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValidatorId {
    length: u16,
    bytes: [u8; MAX_VALIDATOR_ID_BYTES],
}

impl ValidatorId {
    /// Compatibility constructor for existing 32-byte validator identities.
    pub const fn new(value: [u8; 32]) -> Self {
        let mut bytes = [0u8; MAX_VALIDATOR_ID_BYTES];
        let mut index = 0usize;
        while index < value.len() {
            bytes[index] = value[index];
            index += 1;
        }
        Self { length: 32, bytes }
    }

    pub fn from_bytes(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(ValidationError::EmptyValidatorId);
        }
        if value.len() > MAX_VALIDATOR_ID_BYTES {
            return Err(ValidationError::ValidatorIdTooLong {
                actual: value.len(),
                maximum: MAX_VALIDATOR_ID_BYTES,
            });
        }
        let mut bytes = [0u8; MAX_VALIDATOR_ID_BYTES];
        bytes[..value.len()].copy_from_slice(value);
        Ok(Self {
            length: value.len() as u16,
            bytes,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    pub fn is_zero(&self) -> bool {
        self.as_bytes().iter().all(|byte| *byte == 0)
    }
}

impl core::fmt::Debug for ValidatorId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("ValidatorId")
            .field(&self.as_bytes())
            .finish()
    }
}

impl Ord for ValidatorId {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl PartialOrd for ValidatorId {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

macro_rules! counter {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            pub const fn get(self) -> u64 {
                self.0
            }

            pub fn checked_next(self) -> Result<Self> {
                self.0
                    .checked_add(1)
                    .map(Self)
                    .ok_or(ValidationError::ArithmeticOverflow(stringify!($name)))
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self::new(value)
            }
        }
    };
}

counter!(Epoch);
counter!(View);
counter!(Height);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u32);

impl ProtocolVersion {
    pub const V0: Self = Self(0);

    pub fn new(value: u32) -> Result<Self> {
        Ok(Self(value))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VotingPower(u64);

impl VotingPower {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            return Err(ValidationError::ZeroVotingPower);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureBytes([u8; SIGNATURE_BYTES]);

impl SignatureBytes {
    pub const fn from_array(bytes: [u8; SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        Self::from_slice(&bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let actual = bytes.len();
        let array: [u8; SIGNATURE_BYTES] =
            bytes
                .try_into()
                .map_err(|_| ValidationError::InvalidSignatureLength {
                    actual,
                    expected: SIGNATURE_BYTES,
                })?;
        Ok(Self(array))
    }

    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.0
    }

    pub fn validate_shape(&self) -> Result<()> {
        Ok(())
    }
}

pub type Signature64 = SignatureBytes;
