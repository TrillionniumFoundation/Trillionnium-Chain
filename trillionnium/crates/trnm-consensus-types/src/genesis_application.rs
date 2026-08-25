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
    ChainId, GenesisHash, GenesisQcV0, Height, ProtocolVersion, Result, StateRoot, ValidationError,
    ValidatorSet, ValidatorSetId,
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

/// Explicit object profile included in every canonical descriptor preimage.
pub const POCO_GENESIS_PROFILE_V1: &[u8] = b"trnm.poco-bft.migration.genesis.v1";

/// Explicit object profile included in every canonical QC ceremony preimage.
pub const POCO_GENESIS_QC_BINDING_PROFILE_V1: &[u8] =
    b"trnm.poco-bft.migration.genesis-qc-binding.v1";

/// Explicit profile for the legacy Comet BlockID shape embedded in the
/// migration descriptor.
pub const COMET_FINALIZED_BLOCK_IDENTITY_PROFILE_V1: &[u8] =
    b"trnm.poco-bft.migration.comet-block-id.v1";

/// Domain for the content-addressed migration descriptor.
pub const POCO_GENESIS_COMMITMENT_DOMAIN_V1: &[u8] =
    b"trnm.poco-bft.migration.genesis-commitment.v1";

/// Domain for the finalized source-cutoff identity embedded in a migration
/// descriptor.  It is separate from the complete descriptor commitment so a
/// cutoff key cannot accidentally be used as a complete genesis commitment.
pub const POCO_GENESIS_MIGRATION_INSTANCE_DOMAIN_V1: &[u8] = b"trnm.poco-bft.migration.instance.v1";

/// Domain for the explicit GenesisQC-to-migration-descriptor ceremony pair.
pub const POCO_GENESIS_QC_BINDING_DOMAIN_V1: &[u8] =
    b"trnm.poco-bft.migration.genesis-qc-ceremony.v1";

/// Domain for the source namespace identity.  This is intentionally distinct
/// from the migration-instance digest, which also commits the cutoff.
pub const POCO_GENESIS_SOURCE_NAMESPACE_DOMAIN_V1: &[u8] =
    b"trnm.poco-bft.migration.source-namespace.v1";

/// Maximum exact canonical bytes accepted by the migration descriptor decoder.
/// This is checked before any field parsing or object construction.
pub const MAX_POCO_GENESIS_CANONICAL_BYTES_V1: usize = 1024;

/// Maximum exact canonical bytes accepted by the descriptor/QC ceremony
/// decoder, including the bounded embedded QC and descriptor roots.
pub const MAX_POCO_GENESIS_QC_BINDING_CANONICAL_BYTES_V1: usize = 4096;

/// Canonical schema marker for the non-wire application commitment bytes.
pub const GENESIS_APPLICATION_COMMITMENT_SCHEMA_VERSION_V0: u16 = 0;

/// A legacy Comet genesis-document digest. It is deliberately not
/// `GenesisHash`, so a source-chain fork/redeployment cannot be confused with
/// a native PoCO genesis hash at the type boundary. The export specification
/// must define the exact canonical Comet genesis-document preimage that this
/// digest covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyCometGenesisHashV1([u8; 32]);

impl LegacyCometGenesisHashV1 {
    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "legacy Comet genesis identity must be nonzero",
            ));
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The source block identity used by the migration manifest.  Comet's
/// BlockID includes a part-set header; it must not be represented by native
/// PoCO `BlockId` or by a bare header hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CometFinalizedBlockIdentityV1 {
    block_hash: [u8; 32],
    part_set_total: u32,
    part_set_hash: [u8; 32],
}

impl CometFinalizedBlockIdentityV1 {
    pub fn new(block_hash: [u8; 32], part_set_total: u32, part_set_hash: [u8; 32]) -> Result<Self> {
        if block_hash == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "legacy Comet block hash must be nonzero",
            ));
        }
        if part_set_total == 0 {
            return Err(ValidationError::InvalidCertificate(
                "legacy Comet part-set total must be nonzero",
            ));
        }
        if part_set_hash == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "legacy Comet part-set hash must be nonzero",
            ));
        }
        Ok(Self {
            block_hash,
            part_set_total,
            part_set_hash,
        })
    }

    pub const fn block_hash(&self) -> &[u8; 32] {
        &self.block_hash
    }

    pub const fn part_set_total(&self) -> u32 {
        self.part_set_total
    }

    pub const fn part_set_hash(&self) -> &[u8; 32] {
        &self.part_set_hash
    }

    pub fn try_canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_canonical_v1(encoder))
    }

    fn encode_canonical_v1(&self, encoder: &mut Encoder) {
        encoder.u16(POCO_GENESIS_SCHEMA_VERSION_V1);
        encoder.bytes(COMET_FINALIZED_BLOCK_IDENTITY_PROFILE_V1);
        encoder.fixed(&self.block_hash);
        encoder.u32(self.part_set_total);
        encoder.fixed(&self.part_set_hash);
    }
}

/// A legacy Comet AppHash attestation.  It is intentionally distinct from a
/// native PoCO `StateRoot`; the old value can be recorded and signed but can
/// never be passed as the new application root by type substitution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyCometAppHashV1([u8; 32]);

impl LegacyCometAppHashV1 {
    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "legacy Comet AppHash attestation must be nonzero",
            ));
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

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
    source_genesis_hash: LegacyCometGenesisHashV1,
    source_application_id: [u8; 32],
    source_store_id: [u8; 32],
    source_height: Height,
    source_block_identity: CometFinalizedBlockIdentityV1,
    source_finality_proof_digest: [u8; 32],
    legacy_app_hash_attestation: LegacyCometAppHashV1,
    export_manifest_digest: [u8; 32],
    mapping_profile_digest: [u8; 32],
    target_chain_id: ChainId,
    target_genesis_hash: GenesisHash,
    target_genesis_manifest_digest: [u8; 32],
    new_state_root: StateRoot,
    target_validator_set_digest: ValidatorSetId,
    target_protocol_version: ProtocolVersion,
}

impl PocoGenesisV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_chain_id: ChainId,
        source_genesis_hash: LegacyCometGenesisHashV1,
        source_application_id: [u8; 32],
        source_store_id: [u8; 32],
        source_height: Height,
        source_block_identity: CometFinalizedBlockIdentityV1,
        source_finality_proof_digest: [u8; 32],
        legacy_app_hash_attestation: LegacyCometAppHashV1,
        export_manifest_digest: [u8; 32],
        mapping_profile_digest: [u8; 32],
        target_chain_id: ChainId,
        target_genesis_hash: GenesisHash,
        target_genesis_manifest_digest: [u8; 32],
        new_state_root: StateRoot,
        target_validator_set_digest: ValidatorSetId,
        target_protocol_version: ProtocolVersion,
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
                "migration source height must be nonzero",
            ));
        }
        if source_finality_proof_digest == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "source finality proof digest must be nonzero",
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
        if target_genesis_manifest_digest == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "target genesis manifest digest must be nonzero",
            ));
        }
        if new_state_root.is_zero() {
            return Err(ValidationError::InvalidCertificate(
                "new native state root must be nonzero",
            ));
        }
        if target_validator_set_digest.is_zero() {
            return Err(ValidationError::ValidatorSetMismatch);
        }
        if target_protocol_version != ProtocolVersion::V0 {
            return Err(ValidationError::ProtocolVersionMismatch);
        }

        Ok(Self {
            source_chain_id,
            source_genesis_hash,
            source_application_id,
            source_store_id,
            source_height,
            source_block_identity,
            source_finality_proof_digest,
            legacy_app_hash_attestation,
            export_manifest_digest,
            mapping_profile_digest,
            target_chain_id,
            target_genesis_hash,
            target_genesis_manifest_digest,
            new_state_root,
            target_validator_set_digest,
            target_protocol_version,
        })
    }

    pub const fn source_chain_id(&self) -> ChainId {
        self.source_chain_id
    }

    pub const fn source_genesis_hash(&self) -> &LegacyCometGenesisHashV1 {
        &self.source_genesis_hash
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

    pub const fn source_block_identity(&self) -> &CometFinalizedBlockIdentityV1 {
        &self.source_block_identity
    }

    pub const fn source_finality_proof_digest(&self) -> [u8; 32] {
        self.source_finality_proof_digest
    }

    pub const fn legacy_app_hash_attestation(&self) -> &LegacyCometAppHashV1 {
        &self.legacy_app_hash_attestation
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

    pub const fn target_genesis_manifest_digest(&self) -> [u8; 32] {
        self.target_genesis_manifest_digest
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

    /// A stable identity for the source namespace. It excludes the cutoff;
    /// [`migration_instance_digest_v1`](Self::migration_instance_digest_v1)
    /// below commits the finalized height and source block separately.
    pub fn source_namespace_id_v1(&self) -> [u8; 32] {
        hash_len_framed(
            POCO_GENESIS_SOURCE_NAMESPACE_DOMAIN_V1,
            &[
                self.source_chain_id.as_bytes(),
                self.source_genesis_hash.as_bytes(),
                &self.source_application_id,
                &self.source_store_id,
            ],
        )
    }

    /// Anti-replay identity for one complete migration instance.
    ///
    /// This digest includes both the legacy cutoff evidence and the target
    /// ceremony inputs. It must not be interpreted as proof of finality by
    /// itself; `source_finality_proof_digest` remains an opaque reference until
    /// a typed Comet export verifier checks it.
    pub fn migration_instance_digest_v1(&self) -> Result<[u8; 32]> {
        let height = self.source_height.get().to_be_bytes();
        let block = self.source_block_identity.try_canonical_bytes_v1()?;
        let protocol_version = self.target_protocol_version.get().to_be_bytes();
        let source_namespace = self.source_namespace_id_v1();
        Ok(hash_len_framed(
            POCO_GENESIS_MIGRATION_INSTANCE_DOMAIN_V1,
            &[
                &source_namespace,
                &height,
                &block,
                &self.source_finality_proof_digest,
                self.legacy_app_hash_attestation.as_bytes(),
                &self.export_manifest_digest,
                &self.mapping_profile_digest,
                self.target_chain_id.as_bytes(),
                self.target_genesis_hash.as_bytes(),
                &self.target_genesis_manifest_digest,
                self.new_state_root.as_bytes(),
                self.target_validator_set_digest.as_bytes(),
                &protocol_version,
            ],
        ))
    }

    /// Canonical bytes signed/archived by the migration ceremony.
    pub fn try_canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        let source_namespace = self.source_namespace_id_v1();
        let migration_instance = self.migration_instance_digest_v1()?;
        try_canonical_bytes(|encoder| {
            self.encode_canonical_v1(encoder, source_namespace, migration_instance)
        })
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

    /// Binds and then rechecks the descriptor against the exact trusted
    /// validator set used by the importing node. The ordinary binding method
    /// remains available for local construction, but it is not a cross-peer
    /// authority proof.
    pub fn bind_genesis_qc_v1_with_trusted_set(
        self,
        genesis_qc: GenesisQcV0,
        trusted_set: &ValidatorSet,
    ) -> Result<PocoGenesisQcBindingV1> {
        let binding = self.bind_genesis_qc_v1(genesis_qc)?;
        binding.validate_against_trusted_set(trusted_set)?;
        Ok(binding)
    }

    fn encode_canonical_v1(
        &self,
        encoder: &mut Encoder,
        source_namespace: [u8; 32],
        migration_instance: [u8; 32],
    ) {
        encoder.u16(POCO_GENESIS_SCHEMA_VERSION_V1);
        encoder.bytes(POCO_GENESIS_PROFILE_V1);
        encoder.consensus_string(self.source_chain_id.as_bytes());
        encoder.fixed(self.source_genesis_hash.as_bytes());
        encoder.fixed(&self.source_application_id);
        encoder.fixed(&self.source_store_id);
        encoder.u64(self.source_height.get());
        self.source_block_identity.encode_canonical_v1(encoder);
        encoder.fixed(&self.source_finality_proof_digest);
        encoder.fixed(self.legacy_app_hash_attestation.as_bytes());
        encoder.fixed(&self.export_manifest_digest);
        encoder.fixed(&self.mapping_profile_digest);
        encoder.consensus_string(self.target_chain_id.as_bytes());
        encoder.fixed(self.target_genesis_hash.as_bytes());
        encoder.fixed(&self.target_genesis_manifest_digest);
        encoder.fixed(self.new_state_root.as_bytes());
        encoder.fixed(self.target_validator_set_digest.as_bytes());
        encoder.u32(self.target_protocol_version.get());
        encoder.fixed(&source_namespace);
        encoder.fixed(&migration_instance);
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

    /// Rechecks the frozen GenesisQC context and every target descriptor
    /// coordinate against the importer-owned validator set. This still does
    /// not provide a quorum signature or cross-peer ceremony attestation; it
    /// only prevents a caller from pairing a locally valid QC with the wrong
    /// trusted set.
    pub fn validate_against_trusted_set(&self, trusted_set: &ValidatorSet) -> Result<()> {
        self.genesis_qc.matches_trusted_set(trusted_set)?;
        if self.descriptor.target_chain_id() != trusted_set.chain_id() {
            return Err(ValidationError::ChainIdMismatch);
        }
        if self.descriptor.target_genesis_hash() != trusted_set.genesis_hash() {
            return Err(ValidationError::GenesisHashMismatch);
        }
        if self.descriptor.target_validator_set_digest() != trusted_set.id() {
            return Err(ValidationError::ValidatorSetMismatch);
        }
        if self.descriptor.target_protocol_version() != trusted_set.protocol_version() {
            return Err(ValidationError::ProtocolVersionMismatch);
        }
        Ok(())
    }

    pub fn ceremony_digest_v1(&self) -> Result<[u8; 32]> {
        let qc = self.genesis_qc.try_cev0_bytes()?;
        let descriptor = self.descriptor.try_canonical_bytes_v1()?;
        Ok(hash_len_framed(
            POCO_GENESIS_QC_BINDING_DOMAIN_V1,
            &[POCO_GENESIS_QC_BINDING_PROFILE_V1, &qc, &descriptor],
        ))
    }

    pub fn try_canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        let qc = self.genesis_qc.try_cev0_bytes()?;
        let descriptor = self.descriptor.try_canonical_bytes_v1()?;
        let ceremony = self.ceremony_digest_v1()?;
        try_canonical_bytes(|encoder| {
            encoder.u16(POCO_GENESIS_SCHEMA_VERSION_V1);
            encoder.bytes(POCO_GENESIS_QC_BINDING_PROFILE_V1);
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
    use alloc::vec;

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

    fn trusted_set() -> ValidatorSet {
        ValidatorSet::new(
            GenesisHash::new([0xA5; 32]),
            CHAIN,
            ProtocolVersion::V0,
            crate::Epoch::new(0),
            crate::ConsensusParametersHash::new([0xC1; 32]),
            vec![crate::Validator::new(
                crate::ValidatorId::from_bytes(b"validator-a").unwrap(),
                crate::ConsensusPublicKey::new([0xD1; 32]),
                crate::VotingPower::new(1).unwrap(),
            )
            .unwrap()],
        )
        .expect("trusted epoch-zero validator set")
    }

    fn migration_descriptor_for_set(set: &ValidatorSet) -> PocoGenesisV1 {
        PocoGenesisV1::new(
            ChainId::from_static("trnm-source-chain-0"),
            LegacyCometGenesisHashV1::new([0x19; 32]).unwrap(),
            [0x21; 32],
            [0x22; 32],
            Height::new(77),
            CometFinalizedBlockIdentityV1::new([0x23; 32], 1, [0x24; 32]).unwrap(),
            [0x25; 32],
            LegacyCometAppHashV1::new([0x26; 32]).unwrap(),
            [0x27; 32],
            [0x28; 32],
            set.chain_id(),
            set.genesis_hash(),
            [0x29; 32],
            StateRoot::new([0x2A; 32]),
            set.id(),
            ProtocolVersion::V0,
        )
        .expect("set-bound migration descriptor")
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
            LegacyCometGenesisHashV1::new([0x09; 32]).expect("source genesis digest"),
            [0x11; 32],
            [0x22; 32],
            Height::new(77),
            CometFinalizedBlockIdentityV1::new([0x33; 32], 1, [0x34; 32])
                .expect("source Comet block identity"),
            [0x55; 32],
            LegacyCometAppHashV1::new([0x44; 32]).expect("legacy AppHash"),
            [0x66; 32],
            [0x67; 32],
            CHAIN,
            GenesisHash::new([0xA5; 32]),
            [0x88; 32],
            StateRoot::new([0x77; 32]),
            crate::ValidatorSetId::new([0xB6; 32]),
            ProtocolVersion::V0,
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
        assert_ne!(descriptor.source_namespace_id_v1(), [0; 32]);
        assert_ne!(descriptor.migration_instance_digest_v1().unwrap(), [0; 32]);
        assert_ne!(
            descriptor.legacy_app_hash_attestation().as_bytes(),
            descriptor.new_state_root().as_bytes()
        );

        // The fields are private by design; changing a source namespace is
        // represented by reconstructing the exact ceremony input.
        let changed_source = PocoGenesisV1::new(
            descriptor.source_chain_id(),
            LegacyCometGenesisHashV1::new([0x12; 32]).expect("changed source genesis digest"),
            descriptor.source_application_id(),
            [0x12; 32],
            descriptor.source_height(),
            *descriptor.source_block_identity(),
            descriptor.source_finality_proof_digest(),
            *descriptor.legacy_app_hash_attestation(),
            descriptor.export_manifest_digest(),
            descriptor.mapping_profile_digest(),
            descriptor.target_chain_id(),
            descriptor.target_genesis_hash(),
            descriptor.target_genesis_manifest_digest(),
            descriptor.new_state_root(),
            descriptor.target_validator_set_digest(),
            descriptor.target_protocol_version(),
        )
        .expect("changed source descriptor");
        assert_ne!(
            descriptor.source_namespace_id_v1(),
            changed_source.source_namespace_id_v1()
        );
        assert_ne!(
            descriptor.commitment_digest_v1().unwrap(),
            changed_source.commitment_digest_v1().unwrap()
        );
    }

    #[test]
    fn migration_descriptor_instance_changes_with_cutoff_and_target_inputs() {
        let descriptor = migration_descriptor();
        let changed_cutoff = PocoGenesisV1::new(
            descriptor.source_chain_id(),
            *descriptor.source_genesis_hash(),
            descriptor.source_application_id(),
            descriptor.source_store_id(),
            Height::new(descriptor.source_height().get() + 1),
            *descriptor.source_block_identity(),
            descriptor.source_finality_proof_digest(),
            *descriptor.legacy_app_hash_attestation(),
            descriptor.export_manifest_digest(),
            descriptor.mapping_profile_digest(),
            descriptor.target_chain_id(),
            descriptor.target_genesis_hash(),
            descriptor.target_genesis_manifest_digest(),
            descriptor.new_state_root(),
            descriptor.target_validator_set_digest(),
            descriptor.target_protocol_version(),
        )
        .expect("changed source descriptor");
        assert_ne!(
            descriptor.migration_instance_digest_v1().unwrap(),
            changed_cutoff.migration_instance_digest_v1().unwrap()
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
    fn migration_qc_binding_decoder_rechecks_trusted_set_and_exact_profile() {
        let set = trusted_set();
        let descriptor = migration_descriptor_for_set(&set);
        let qc = GenesisQcV0::new(set.genesis_hash(), set.chain_id(), &set).unwrap();
        let binding = descriptor
            .bind_genesis_qc_v1_with_trusted_set(qc, &set)
            .expect("trusted set-bound ceremony");
        let bytes = binding.try_canonical_bytes_v1().unwrap();
        assert_eq!(
            crate::decode_poco_genesis_qc_binding_v1_exact(&bytes, &set).unwrap(),
            binding
        );

        let mut tampered = bytes.clone();
        // The first two bytes are the schema and the next four bytes are the
        // profile length; flip the first profile byte without changing its
        // framing so the decoder must reject the object kind.
        tampered[6] ^= 1;
        let error = crate::decode_poco_genesis_qc_binding_v1_exact(&tampered, &set)
            .expect_err("profile mutation must fail closed");
        assert_eq!(error.code(), crate::DecodeErrorCode::ContextMismatch);
    }

    #[test]
    fn migration_descriptor_rejects_reuse_of_source_chain_or_unfinalized_height() {
        let same_chain = PocoGenesisV1::new(
            CHAIN,
            LegacyCometGenesisHashV1::new([1; 32]).unwrap(),
            [1; 32],
            [2; 32],
            Height::new(1),
            CometFinalizedBlockIdentityV1::new([3; 32], 1, [4; 32]).unwrap(),
            [5; 32],
            LegacyCometAppHashV1::new([6; 32]).unwrap(),
            [6; 32],
            [7; 32],
            CHAIN,
            GenesisHash::new([7; 32]),
            [8; 32],
            StateRoot::new([8; 32]),
            crate::ValidatorSetId::new([9; 32]),
            ProtocolVersion::V0,
        );
        assert!(matches!(
            same_chain,
            Err(ValidationError::InvalidCertificate(_))
        ));

        let zero_height = PocoGenesisV1::new(
            ChainId::from_static("trnm-source-chain-0"),
            LegacyCometGenesisHashV1::new([1; 32]).unwrap(),
            [1; 32],
            [2; 32],
            Height::new(0),
            CometFinalizedBlockIdentityV1::new([3; 32], 1, [4; 32]).unwrap(),
            [5; 32],
            LegacyCometAppHashV1::new([6; 32]).unwrap(),
            [6; 32],
            [7; 32],
            CHAIN,
            GenesisHash::new([7; 32]),
            [8; 32],
            StateRoot::new([8; 32]),
            crate::ValidatorSetId::new([9; 32]),
            ProtocolVersion::V0,
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
