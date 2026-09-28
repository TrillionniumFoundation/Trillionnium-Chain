#![forbid(unsafe_code)]
//! Generic owner-frontier checkpoint and CAS contract. No ledger voting or finality.
//! Version 2 is a fresh namespace; legacy databases are not upgraded in place.
mod record;
pub use record::*;

macro_rules! hash_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name([u8; 32]);
        impl $name {
            pub const fn new(value: [u8; 32]) -> Self {
                Self(value)
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
    };
}
hash_type!(BlockId);
hash_type!(StateRoot);

/// Immutable journal frontier; this value is not an execution capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectWatermarkV2 {
    scope: [u8; 32],
    journal_id: [u8; 32],
    sequence: u64,
    chain_checksum: [u8; 32],
}
impl EffectWatermarkV2 {
    pub fn from_persisted_parts(
        scope: [u8; 32],
        journal_id: [u8; 32],
        sequence: u64,
        chain_checksum: [u8; 32],
    ) -> Result<Self, ExternalCheckpointDecodeErrorV2> {
        if scope == [0; 32] || journal_id == [0; 32] || chain_checksum == [0; 32] {
            return Err(ExternalCheckpointDecodeErrorV2::InvalidField(
                "effect watermark",
            ));
        }
        Ok(Self {
            scope,
            journal_id,
            sequence,
            chain_checksum,
        })
    }
    pub const fn scope(&self) -> [u8; 32] {
        self.scope
    }
    pub const fn journal_id(&self) -> [u8; 32] {
        self.journal_id
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn chain_checksum(&self) -> [u8; 32] {
        self.chain_checksum
    }
}
