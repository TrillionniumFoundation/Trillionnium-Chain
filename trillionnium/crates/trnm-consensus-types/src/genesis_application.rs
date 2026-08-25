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
    BlockId, ChainId, GenesisHash, GenesisQcV0, Height, ProtocolVersion, Result, StateRoot,
    ValidationError, ValidatorSet, ValidatorSetId,
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

/// Canonical schema marker for the first migration-aware PoCO genesis
/// descriptor.  This is an application/ceremony object, not a replacement
/// for the frozen GenesisQC v0 wire object.
pub const POCO_GENESIS_SCHEMA_VERSION_V1: u16 = 1;

/// Domain for the content-addressed migration descriptor.
pub const POCO_GENESIS_COMMITMENT_DOMAIN_V1: &[u8] =
    b"trnm.consensus-types.poco-genesis-commitment.v1";

/// Domain for the explicit GenesisQC-to-migration-descriptor ceremony pair.
pub const POCO_GENESIS_QC_BINDING_DOMAIN_V1: &[u8] =
    b"trnm.consensus-types.poco-genesis-qc-ceremony.v1";

/// Maximum exact canonical bytes accepted by the migration descriptor decoder.
/// This is checked before any field parsing or object construction.
pub const MAX_POCO_GENESIS_CANONICAL_BYTES_V1: usize = 1024;

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

/// The deterministic, content-addressed descriptor imported when a finalized
/// legacy chain is cut over to a fresh native PoCO data directory.
///
/// The descriptor deliberately carries the old AppHash only as an attestation
/// field.  `new_state_root` is an independently recomputed native root and is
/// never inferred from that old value.  All fields are immutable ceremony
/// inputs; a node must verify the descriptor and the source manifest before it
/// creates its first PoCO block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoGenesisV1 {
    source_chain_id: ChainId,
    source_application_id: [u8; 32],
    source_store_id: [u8; 32],
    source_height: Height,
    source_block_id: BlockId,
    legacy_app_hash_attestation: StateRoot,
    export_manifest_digest: [u8; 32],
    mapping_profile_digest: [u8; 32],
    target_chain_id: ChainId,
    target_genesis_hash: GenesisHash,
    new_state_root: StateRoot,
    target_validator_set_digest: ValidatorSetId,
    target_protocol_version: ProtocolVersion,
    genesis_descriptor_digest: [u8; 32],
}

impl PocoGenesisV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_chain_id: ChainId,
        source_application_id: [u8; 32],
        source_store_id: [u8; 32],
        source_height: Height,
        source_block_id: BlockId,
        legacy_app_hash_attestation: StateRoot,
        export_manifest_digest: [u8; 32],
        mapping_profile_digest: [u8; 32],
        target_chain_id: ChainId,
        target_genesis_hash: GenesisHash,
        new_state_root: StateRoot,
        target_validator_set_digest: ValidatorSetId,
        target_protocol_version: ProtocolVersion,
        genesis_descriptor_digest: [u8; 32],
    ) -> Result<Self> {
        if source_chain_id == target_chain_id {
            return Err(ValidationError::InvalidCertificate(
                "PoCO migration must use a fresh target chain id",
            ));
        }
        if source_application_id == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "source application id must be nonzero",
            ));
        }
        if source_store_id == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "source store id must be nonzero",
            ));
        }
        if source_height.get() == 0 {
            return Err(ValidationError::InvalidCertificate(
                "migration source height must be finalized and nonzero",
            ));
        }
        if source_block_id.is_zero() {
            return Err(ValidationError::InvalidCertificate(
                "migration source block id must be nonzero",
            ));
        }
        if legacy_app_hash_attestation.is_zero() {
            return Err(ValidationError::InvalidCertificate(
                "legacy AppHash attestation must be nonzero",
            ));
        }
        if export_manifest_digest == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "export manifest digest must be nonzero",
            ));
        }
        if mapping_profile_digest == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "mapping/profile digest must be nonzero",
            ));
        }
        if target_genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        if new_state_root.is_zero() {
            return Err(ValidationError::InvalidCertificate(
                "new native state root must be nonzero",
            ));
        }
        if target_validator_set_digest.is_zero() {
            return Err(ValidationError::ValidatorSetMismatch);
        }
        if genesis_descriptor_digest == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "genesis descriptor digest must be nonzero",
            ));
        }

        Ok(Self {
            source_chain_id,
            source_application_id,
            source_store_id,
            source_height,
            source_block_id,
            legacy_app_hash_attestation,
            export_manifest_digest,
            mapping_profile_digest,
            target_chain_id,
            target_genesis_hash,
            new_state_root,
            target_validator_set_digest,
            target_protocol_version,
            genesis_descriptor_digest,
        })
    }

    pub const fn source_chain_id(&self) -> ChainId {
        self.source_chain_id
    }

    pub const fn source_application_id(&self) -> [u8; 32] {
        self.source_application_id
    }

    pub const fn source_store_id(&self) -> [u8; 32] {
        self.source_store_id
    }

    pub const fn source_height(&self) -> Height {
        self.source_height
    }

    pub const fn source_block_id(&self) -> BlockId {
        self.source_block_id
    }

    pub const fn legacy_app_hash_attestation(&self) -> StateRoot {
        self.legacy_app_hash_attestation
    }

    pub const fn export_manifest_digest(&self) -> [u8; 32] {
        self.export_manifest_digest
    }

    pub const fn mapping_profile_digest(&self) -> [u8; 32] {
        self.mapping_profile_digest
    }

    pub const fn target_chain_id(&self) -> ChainId {
        self.target_chain_id
    }

    pub const fn target_genesis_hash(&self) -> GenesisHash {
        self.target_genesis_hash
    }

    pub const fn new_state_root(&self) -> StateRoot {
        self.new_state_root
    }

    pub const fn target_validator_set_digest(&self) -> ValidatorSetId {
        self.target_validator_set_digest
    }

    pub const fn target_protocol_version(&self) -> ProtocolVersion {
        self.target_protocol_version
    }

    pub const fn genesis_descriptor_digest(&self) -> [u8; 32] {
        self.genesis_descriptor_digest
    }

    /// A stable identity for the source namespace.  This is included in the
    /// descriptor preimage rather than accepted as an operator-local label.
    pub fn source_identity_v1(&self) -> [u8; 32] {
        hash_len_framed(
            b"trnm.consensus-types.poco-genesis-source-identity.v1",
            &[
                self.source_chain_id.as_bytes(),
                &self.source_application_id,
                &self.source_store_id,
            ],
        )
    }

    /// Canonical bytes signed/archived by the migration ceremony.
    pub fn try_canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_canonical_v1(encoder))
    }

    /// Content address of the complete migration descriptor.
    pub fn commitment_digest_v1(&self) -> Result<[u8; 32]> {
        let bytes = self.try_canonical_bytes_v1()?;
        Ok(hash_len_framed(
            POCO_GENESIS_COMMITMENT_DOMAIN_V1,
            &[&bytes],
        ))
    }

    /// Binds the descriptor to the target synthetic GenesisQC context.  This
    /// wrapper is the migration-era ceremony boundary; it intentionally does
    /// not mutate the frozen GenesisQC v0 bytes or claim production activation.
    pub fn bind_genesis_qc_v1(self, genesis_qc: GenesisQcV0) -> Result<PocoGenesisQcBindingV1> {
        if genesis_qc.genesis_hash() != self.target_genesis_hash {
            return Err(ValidationError::GenesisHashMismatch);
        }
        if genesis_qc.chain_id() != self.target_chain_id {
            return Err(ValidationError::ChainIdMismatch);
        }
        if genesis_qc.validator_set_hash() != self.target_validator_set_digest {
            return Err(ValidationError::ValidatorSetMismatch);
        }
        if genesis_qc.protocol_version() != self.target_protocol_version {
            return Err(ValidationError::ProtocolVersionMismatch);
        }
        Ok(PocoGenesisQcBindingV1 {
            genesis_qc,
            descriptor: self,
        })
    }

    fn encode_canonical_v1(&self, encoder: &mut Encoder) {
        encoder.u16(POCO_GENESIS_SCHEMA_VERSION_V1);
        encoder.consensus_string(self.source_chain_id.as_bytes());
        encoder.fixed(&self.source_application_id);
        encoder.fixed(&self.source_store_id);
        encoder.u64(self.source_height.get());
        encoder.fixed(self.source_block_id.as_bytes());
        encoder.fixed(self.legacy_app_hash_attestation.as_bytes());
        encoder.fixed(&self.export_manifest_digest);
        encoder.fixed(&self.mapping_profile_digest);
        encoder.consensus_string(self.target_chain_id.as_bytes());
        encoder.fixed(self.target_genesis_hash.as_bytes());
        encoder.fixed(self.new_state_root.as_bytes());
        encoder.fixed(self.target_validator_set_digest.as_bytes());
        encoder.u32(self.target_protocol_version.get());
        encoder.fixed(&self.genesis_descriptor_digest);
        encoder.fixed(&self.source_identity_v1());
    }
}

/// Explicit ceremony pair for a migration-aware genesis descriptor and the
/// target synthetic GenesisQC.  The old GenesisQC's id/bytes remain unchanged;
/// callers must commit this pair's digest in the versioned genesis ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoGenesisQcBindingV1 {
    genesis_qc: GenesisQcV0,
    descriptor: PocoGenesisV1,
}

impl PocoGenesisQcBindingV1 {
    pub const fn genesis_qc_v0(&self) -> &GenesisQcV0 {
        &self.genesis_qc
    }

    pub const fn descriptor_v1(&self) -> &PocoGenesisV1 {
        &self.descriptor
    }

    pub fn ceremony_digest_v1(&self) -> Result<[u8; 32]> {
        let qc = self.genesis_qc.try_cev0_bytes()?;
        let descriptor = self.descriptor.try_canonical_bytes_v1()?;
        Ok(hash_len_framed(
            POCO_GENESIS_QC_BINDING_DOMAIN_V1,
            &[&qc, &descriptor],
        ))
    }

    pub fn try_canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        let qc = self.genesis_qc.try_cev0_bytes()?;
        let descriptor = self.descriptor.try_canonical_bytes_v1()?;
        let ceremony = self.ceremony_digest_v1()?;
        try_canonical_bytes(|encoder| {
            encoder.u16(POCO_GENESIS_SCHEMA_VERSION_V1);
            encoder.bytes(&qc);
            encoder.bytes(&descriptor);
            encoder.fixed(&ceremony);
        })
    }

    pub fn into_parts(self) -> (GenesisQcV0, PocoGenesisV1) {
        (self.genesis_qc, self.descriptor)
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

    fn migration_descriptor() -> PocoGenesisV1 {
        PocoGenesisV1::new(
            ChainId::from_static("trnm-source-chain-0"),
            [0x11; 32],
            [0x22; 32],
            Height::new(77),
            BlockId::new([0x33; 32]),
            StateRoot::new([0x44; 32]),
            [0x55; 32],
            [0x66; 32],
            CHAIN,
            GenesisHash::new([0xA5; 32]),
            StateRoot::new([0x77; 32]),
            crate::ValidatorSetId::new([0xB6; 32]),
            ProtocolVersion::V0,
            [0x88; 32],
        )
        .expect("shape-valid migration descriptor")
    }

    #[test]
    fn migration_descriptor_binds_source_and_new_native_root_without_root_substitution() {
        let descriptor = migration_descriptor();
        let bytes = descriptor
            .try_canonical_bytes_v1()
            .expect("canonical migration descriptor");
        let digest = descriptor
            .commitment_digest_v1()
            .expect("migration descriptor digest");
        assert_eq!(bytes.first().copied(), Some(0));
        assert_ne!(digest, [0; 32]);
        assert_ne!(descriptor.source_identity_v1(), [0; 32]);
        assert_ne!(
            descriptor.legacy_app_hash_attestation(),
            descriptor.new_state_root()
        );

        // The fields are private by design; changing a source namespace is
        // represented by reconstructing the exact ceremony input.
        let changed_source = PocoGenesisV1::new(
            descriptor.source_chain_id(),
            [0x12; 32],
            descriptor.source_store_id(),
            descriptor.source_height(),
            descriptor.source_block_id(),
            descriptor.legacy_app_hash_attestation(),
            descriptor.export_manifest_digest(),
            descriptor.mapping_profile_digest(),
            descriptor.target_chain_id(),
            descriptor.target_genesis_hash(),
            descriptor.new_state_root(),
            descriptor.target_validator_set_digest(),
            descriptor.target_protocol_version(),
            descriptor.genesis_descriptor_digest(),
        )
        .expect("changed source descriptor");
        assert_ne!(
            descriptor.source_identity_v1(),
            changed_source.source_identity_v1()
        );
        assert_ne!(
            descriptor.commitment_digest_v1().unwrap(),
            changed_source.commitment_digest_v1().unwrap()
        );
    }

    #[test]
    fn migration_descriptor_qc_ceremony_preserves_frozen_qc_and_rejects_foreign_context() {
        let descriptor = migration_descriptor();
        let qc = test_qc();
        let old_bytes = qc.try_cev0_bytes().expect("frozen QC bytes");
        let old_id = qc.id();
        let binding = descriptor
            .clone()
            .bind_genesis_qc_v1(qc.clone())
            .expect("target QC matches migration descriptor");
        assert_eq!(binding.genesis_qc_v0(), &qc);
        assert_eq!(qc.try_cev0_bytes().unwrap(), old_bytes);
        assert_eq!(qc.id(), old_id);
        assert_ne!(binding.ceremony_digest_v1().unwrap(), [0; 32]);
        assert!(!binding.try_canonical_bytes_v1().unwrap().is_empty());

        let foreign = GenesisQcV0::from_parts_for_test(
            GenesisHash::new([0xA5; 32]),
            ChainId::from_static("trnm-foreign-chain-0"),
            crate::ValidatorSetId::new([0xB6; 32]),
        )
        .expect("foreign QC");
        assert_eq!(
            descriptor.bind_genesis_qc_v1(foreign).unwrap_err(),
            ValidationError::ChainIdMismatch
        );
    }

    #[test]
    fn migration_descriptor_rejects_reuse_of_source_chain_or_unfinalized_height() {
        let same_chain = PocoGenesisV1::new(
            CHAIN,
            [1; 32],
            [2; 32],
            Height::new(1),
            BlockId::new([3; 32]),
            StateRoot::new([4; 32]),
            [5; 32],
            [6; 32],
            CHAIN,
            GenesisHash::new([7; 32]),
            StateRoot::new([8; 32]),
            crate::ValidatorSetId::new([9; 32]),
            ProtocolVersion::V0,
            [10; 32],
        );
        assert!(matches!(
            same_chain,
            Err(ValidationError::InvalidCertificate(_))
        ));

        let zero_height = PocoGenesisV1::new(
            ChainId::from_static("trnm-source-chain-0"),
            [1; 32],
            [2; 32],
            Height::new(0),
            BlockId::new([3; 32]),
            StateRoot::new([4; 32]),
            [5; 32],
            [6; 32],
            CHAIN,
            GenesisHash::new([7; 32]),
            StateRoot::new([8; 32]),
            crate::ValidatorSetId::new([9; 32]),
            ProtocolVersion::V0,
            [10; 32],
        );
        assert!(matches!(
            zero_height,
            Err(ValidationError::InvalidCertificate(_))
        ));
    }

    #[test]
    fn migration_descriptor_decoder_is_exact_and_bounded() {
        let descriptor = migration_descriptor();
        let bytes = descriptor
            .try_canonical_bytes_v1()
            .expect("canonical migration descriptor");
        assert_eq!(
            crate::decode_poco_genesis_v1_exact(&bytes).expect("exact descriptor decode"),
            descriptor
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        let trailing_error = crate::decode_poco_genesis_v1_exact(&trailing).unwrap_err();
        assert_eq!(trailing_error.code(), crate::DecodeErrorCode::TrailingBytes);
        assert_eq!(trailing_error.byte_offset(), bytes.len());

        let mut wrong_schema = bytes;
        wrong_schema[1] = 2;
        let schema_error = crate::decode_poco_genesis_v1_exact(&wrong_schema).unwrap_err();
        assert_eq!(
            schema_error.code(),
            crate::DecodeErrorCode::InvalidSchemaVersion
        );
        assert_eq!(schema_error.byte_offset(), 0);
    }
}
