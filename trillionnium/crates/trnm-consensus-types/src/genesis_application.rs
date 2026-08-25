//! Additive genesis-application ceremony bindings.
//!
//! `GenesisQcV0` is a frozen, empty-signature CEV0 anchor.  Its bytes and
//! digest intentionally remain unchanged.  The values in this module are a
//! separate, opt-in commissioning envelope which lets a caller bind the
//! exact application parent used for an authenticated genesis bootstrap to
//! that anchor without changing the old peer/wire object.

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::{
    canonical::{try_canonical_bytes, Encoder},
    GenesisHash, GenesisQcV0, Result, StateRoot, ValidationError, ValidatorSet,
};

/// Domain used by the legacy authenticated-genesis parent comparison digest.
///
/// This is deliberately the same byte string as the consensus-core carrier
/// domain.  Keeping the preimage identical means a parent converted into this
/// independent commitment retains all existing request/persistence binding
/// references byte-for-byte.
pub const GENESIS_APPLICATION_COMMITMENT_BINDING_DOMAIN_V0: &[u8] =
    b"trnm.consensus-core.authenticated-genesis-application-parent.v0";

/// Domain for the additive GenesisQC/application ceremony reference.
pub const GENESIS_QC_APPLICATION_BINDING_DOMAIN_V0: &[u8] =
    b"trnm.consensus-types.genesis-qc-application-ceremony.v0";

/// Canonical schema marker for the non-wire application commitment bytes.
pub const GENESIS_APPLICATION_COMMITMENT_SCHEMA_VERSION_V0: u16 = 0;

/// Exact application state parent which an authenticated synthetic genesis
/// is expected to install.
///
/// This is inert comparison data.  It does not authenticate a peer by itself;
/// the strict core commissioning entry point compares it to the operator's
/// configured parent and to the trusted GenesisQC context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisApplicationCommitmentV0 {
    genesis_hash: GenesisHash,
    timestamp_ms: u64,
    state_version: u64,
    state_root: StateRoot,
    descriptor_ref: [u8; 32],
    projection_profile_ref: [u8; 32],
}

impl GenesisApplicationCommitmentV0 {
    /// Constructs one version-zero application commitment.
    pub fn new(
        genesis_hash: GenesisHash,
        timestamp_ms: u64,
        state_version: u64,
        state_root: StateRoot,
        descriptor_ref: [u8; 32],
        projection_profile_ref: [u8; 32],
    ) -> Result<Self> {
        if state_version != 0 {
            return Err(ValidationError::InvalidCertificate(
                "genesis application commitment state version must be zero",
            ));
        }
        if genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        if state_root.is_zero() {
            return Err(ValidationError::InvalidCertificate(
                "genesis application commitment state root must be nonzero",
            ));
        }
        if descriptor_ref == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "genesis application commitment descriptor reference must be nonzero",
            ));
        }
        if projection_profile_ref == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "genesis application commitment projection profile reference must be nonzero",
            ));
        }
        Ok(Self {
            genesis_hash,
            timestamp_ms,
            state_version,
            state_root,
            descriptor_ref,
            projection_profile_ref,
        })
    }

    pub const fn genesis_hash(&self) -> GenesisHash {
        self.genesis_hash
    }

    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    pub const fn state_version(&self) -> u64 {
        self.state_version
    }

    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    pub const fn descriptor_ref(&self) -> [u8; 32] {
        self.descriptor_ref
    }

    pub const fn projection_profile_ref(&self) -> [u8; 32] {
        self.projection_profile_ref
    }

    /// The legacy parent binding reference, with the exact historical
    /// domain/framing preserved for compatibility with request and record
    /// fingerprints already emitted by consensus-core.
    pub fn binding_ref_v0(&self) -> [u8; 32] {
        let timestamp = self.timestamp_ms.to_be_bytes();
        let state_version = self.state_version.to_be_bytes();
        hash_len_framed(
            GENESIS_APPLICATION_COMMITMENT_BINDING_DOMAIN_V0,
            &[
                self.genesis_hash.as_bytes(),
                &timestamp,
                &state_version,
                self.state_root.as_bytes(),
                &self.descriptor_ref,
                &self.projection_profile_ref,
            ],
        )
    }

    /// Canonical bytes for the additive ceremony envelope.  These bytes are
    /// intentionally not inserted into the frozen CEV0 GenesisQC encoding.
    pub fn try_canonical_bytes_v0(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_canonical_v0(encoder))
    }

    fn encode_canonical_v0(&self, encoder: &mut Encoder) {
        encoder.u16(GENESIS_APPLICATION_COMMITMENT_SCHEMA_VERSION_V0);
        encoder.fixed(self.genesis_hash.as_bytes());
        encoder.u64(self.timestamp_ms);
        encoder.u64(self.state_version);
        encoder.fixed(self.state_root.as_bytes());
        encoder.fixed(&self.descriptor_ref);
        encoder.fixed(&self.projection_profile_ref);
    }
}

/// An opt-in commissioning envelope pairing the frozen GenesisQC with the
/// exact application parent it is intended to initialize.
///
/// The wrapper is not a `QuorumCertificate`, is not accepted by ordinary CEV0
/// decoders, and cannot alter `GenesisQcV0::id` or `try_cev0_bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisQcApplicationBindingV0 {
    genesis_qc: GenesisQcV0,
    application_commitment: GenesisApplicationCommitmentV0,
}

impl GenesisQcApplicationBindingV0 {
    /// Pairs a GenesisQC and application commitment only when they name the
    /// same genesis hash.
    pub fn new(
        genesis_qc: GenesisQcV0,
        application_commitment: GenesisApplicationCommitmentV0,
    ) -> Result<Self> {
        if genesis_qc.genesis_hash() != application_commitment.genesis_hash() {
            return Err(ValidationError::GenesisHashMismatch);
        }
        Ok(Self {
            genesis_qc,
            application_commitment,
        })
    }

    pub const fn genesis_qc_v0(&self) -> &GenesisQcV0 {
        &self.genesis_qc
    }

    pub const fn application_commitment_v0(&self) -> GenesisApplicationCommitmentV0 {
        self.application_commitment
    }

    pub const fn genesis_hash(&self) -> GenesisHash {
        self.genesis_qc.genesis_hash()
    }

    /// Rechecks both the trusted validator-set context and the local pair
    /// invariant before a strict core commissioning call consumes the value.
    pub fn validate_against_trusted_set(&self, validator_set: &ValidatorSet) -> Result<()> {
        self.genesis_qc.matches_trusted_set(validator_set)?;
        if self.genesis_qc.genesis_hash() != self.application_commitment.genesis_hash() {
            return Err(ValidationError::GenesisHashMismatch);
        }
        Ok(())
    }

    /// Deterministic domain-separated reference for the complete ceremony
    /// pair.  This is an inert reference, not a signature or peer-auth proof.
    pub fn ceremony_ref_v0(&self) -> Result<[u8; 32]> {
        let genesis_qc = self.genesis_qc.try_cev0_bytes()?;
        let application = self.application_commitment.try_canonical_bytes_v0()?;
        Ok(hash_len_framed(
            GENESIS_QC_APPLICATION_BINDING_DOMAIN_V0,
            &[&genesis_qc, &application],
        ))
    }

    /// Consumes the wrapper into its independently typed parts.
    pub fn into_parts(self) -> (GenesisQcV0, GenesisApplicationCommitmentV0) {
        (self.genesis_qc, self.application_commitment)
    }
}

fn hash_len_framed(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"trnm.domain.hash.v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChainId;

    const CHAIN: ChainId = ChainId::from_static("trnm-genesis-binding-test-0");

    fn test_qc() -> GenesisQcV0 {
        GenesisQcV0::from_parts_for_test(
            GenesisHash::new([0xA5; 32]),
            CHAIN,
            crate::ValidatorSetId::new([0xB6; 32]),
        )
        .expect("test GenesisQC")
    }

    fn commitment(root: u8, descriptor: u8, profile: u8) -> GenesisApplicationCommitmentV0 {
        GenesisApplicationCommitmentV0::new(
            GenesisHash::new([0xA5; 32]),
            7,
            0,
            StateRoot::new([root; 32]),
            [descriptor; 32],
            [profile; 32],
        )
        .expect("shape-valid application commitment")
    }

    #[test]
    fn application_binding_is_additive_and_preserves_raw_genesis_qc() {
        let qc = test_qc();
        let old_bytes = qc.try_cev0_bytes().expect("raw GenesisQC bytes");
        let old_id = qc.id();
        let binding = GenesisQcApplicationBindingV0::new(qc.clone(), commitment(0x31, 0x41, 0x51))
            .expect("same-hash binding");

        assert_eq!(
            qc.try_cev0_bytes().expect("raw bytes remain stable"),
            old_bytes
        );
        assert_eq!(qc.id(), old_id);
        assert_eq!(binding.genesis_qc_v0(), &qc);
        assert!(binding.ceremony_ref_v0().is_ok());
    }

    #[test]
    fn application_binding_rejects_hash_mismatch_and_mutations_change_refs() {
        let qc = test_qc();
        let wrong_hash = GenesisApplicationCommitmentV0::new(
            GenesisHash::new([0xC7; 32]),
            7,
            0,
            StateRoot::new([0x31; 32]),
            [0x41; 32],
            [0x51; 32],
        )
        .expect("shape-valid foreign commitment");
        assert_eq!(
            GenesisQcApplicationBindingV0::new(qc.clone(), wrong_hash).unwrap_err(),
            ValidationError::GenesisHashMismatch
        );

        let first = commitment(0x31, 0x41, 0x51);
        let changed = commitment(0x32, 0x41, 0x51);
        assert_ne!(first.binding_ref_v0(), changed.binding_ref_v0());
        let first_binding = GenesisQcApplicationBindingV0::new(qc.clone(), first).unwrap();
        let changed_binding = GenesisQcApplicationBindingV0::new(qc, changed).unwrap();
        assert_ne!(
            first_binding.ceremony_ref_v0().unwrap(),
            changed_binding.ceremony_ref_v0().unwrap()
        );
    }

    #[test]
    fn commitment_shape_rejects_nonzero_version_and_zero_fields() {
        let hash = GenesisHash::new([0xA5; 32]);
        assert!(matches!(
            GenesisApplicationCommitmentV0::new(
                hash,
                0,
                1,
                StateRoot::new([1; 32]),
                [2; 32],
                [3; 32],
            ),
            Err(ValidationError::InvalidCertificate(_))
        ));
        assert!(matches!(
            GenesisApplicationCommitmentV0::new(
                hash,
                0,
                0,
                StateRoot::new([0; 32]),
                [2; 32],
                [3; 32],
            ),
            Err(ValidationError::InvalidCertificate(_))
        ));
    }
}
