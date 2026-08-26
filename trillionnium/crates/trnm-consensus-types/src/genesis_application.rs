//! Additive genesis-application ceremony bindings.
//!
//! `GenesisQcV0` is a frozen, empty-signature CEV0 anchor.  Its bytes and
//! digest intentionally remain unchanged.  The values in this module are a
//! separate, opt-in commissioning envelope which lets a caller bind the
//! exact application parent used for an authenticated genesis bootstrap to
//! that anchor without changing the old peer/wire object.

use alloc::{boxed::Box, vec::Vec};

use sha2::{Digest, Sha256};

use crate::{
    canonical::{signing_root, try_canonical_bytes, Encoder},
    ChainId, GenesisHash, GenesisQcV0, Height, ProtocolVersion, Result, Signature64,
    SignatureVerifier, SigningRoot, StateRoot, ValidationError, ValidatorId, ValidatorSet,
    ValidatorSetId, MAX_VALIDATORS, MAX_VALIDATOR_ID_BYTES, SIGNATURE_BYTES,
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

/// Schema marker for the nested legacy Comet block identity object.
pub const COMET_BLOCK_IDENTITY_SCHEMA_VERSION_V1: u16 = 1;

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

/// Schema marker for the inert target-validator quorum evidence envelope.
/// This is additive evidence and is not the frozen GenesisQC v0 wire object.
pub const GENESIS_QC_CEREMONY_SCHEMA_VERSION_V1: u16 = 1;

/// Explicit object profile for target-validator genesis quorum evidence.
pub const GENESIS_QC_CEREMONY_PROFILE_V1: &[u8] = b"trnm.poco-bft.migration.genesis-qc-quorum.v1";

/// Domain for the statement signed by each target validator. This must never
/// be reused for an ordinary QC, handoff vote, or epoch-anchor signature.
pub const GENESIS_QC_CEREMONY_SIGNING_DOMAIN_V1: &[u8] =
    b"trnm.poco-bft.migration.genesis-qc-sign.v1";

/// Domain for the content address of the complete quorum-evidence envelope.
pub const GENESIS_QC_CEREMONY_COMMITMENT_DOMAIN_V1: &[u8] =
    b"trnm.poco-bft.migration.genesis-qc-quorum-commitment.v1";

/// Role tag included in the v1 signing root. Source/legacy quorum evidence is
/// intentionally a future, separately typed extension once source keys and
/// finality preimages are independently verified.
pub const GENESIS_QC_CEREMONY_TARGET_ROLE_V1: u8 = 1;

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

/// Maximum signature shares in one target quorum-evidence envelope.
pub const MAX_GENESIS_QC_CEREMONY_SIGNATURES_V1: usize = MAX_VALIDATORS;

/// Exact pre-parse ceiling for a target quorum-evidence envelope. The bound
/// is derived from the nested binding, the maximum validator count and the
/// canonical validator-id/signature widths rather than an arbitrary message
/// budget.
pub const MAX_GENESIS_QC_CEREMONY_CANONICAL_BYTES_V1: usize = 2
    + 4
    + GENESIS_QC_CEREMONY_PROFILE_V1.len()
    + 4
    + MAX_POCO_GENESIS_QC_BINDING_CANONICAL_BYTES_V1
    + 4
    + MAX_GENESIS_QC_CEREMONY_SIGNATURES_V1 * (4 + MAX_VALIDATOR_ID_BYTES + SIGNATURE_BYTES);

/// Canonical schema marker for the read-only legacy-state export manifest.
pub const COMET_STATE_EXPORT_SCHEMA_VERSION_V1: u16 = 1;

/// Explicit object profile for a `CometStateExportV1` manifest.
pub const COMET_STATE_EXPORT_PROFILE_V1: &[u8] = b"trnm.poco-bft.migration.comet-state-export.v1";

/// Domain for the content-addressed source export manifest.
pub const COMET_STATE_EXPORT_COMMITMENT_DOMAIN_V1: &[u8] =
    b"trnm.poco-bft.migration.comet-state-export-commitment.v1";

/// Maximum exact canonical bytes accepted for one source export manifest.
pub const MAX_COMET_STATE_EXPORT_CANONICAL_BYTES_V1: usize = 2048;

/// Canonical schema marker for the importer-owned target projection statement.
/// This is deliberately separate from `PocoGenesisV1`: it is a pre-activation
/// replay result, not a genesis or consensus object.
pub const POCO_TARGET_PROJECTION_SCHEMA_VERSION_V1: u16 = 1;

/// Explicit profile for the target projection/root recomputation statement.
pub const POCO_TARGET_PROJECTION_PROFILE_V1: &[u8] =
    b"trnm.poco-bft.migration.target-projection.v1";

/// Domain for the content-addressed target projection statement.
pub const POCO_TARGET_PROJECTION_COMMITMENT_DOMAIN_V1: &[u8] =
    b"trnm.poco-bft.migration.target-projection-commitment.v1";

/// Canonical schema marker for the importer-owned target genesis manifest.
/// This is an inert manifest preimage; it is not a node-start or activation
/// instruction.
pub const POCO_TARGET_GENESIS_MANIFEST_SCHEMA_VERSION_V1: u16 = 1;

/// Explicit profile for the target genesis manifest preimage.
pub const POCO_TARGET_GENESIS_MANIFEST_PROFILE_V1: &[u8] =
    b"trnm.poco-bft.migration.target-genesis-manifest.v1";

/// Domain for the content-addressed target genesis manifest commitment.
pub const POCO_TARGET_GENESIS_MANIFEST_COMMITMENT_DOMAIN_V1: &[u8] =
    b"trnm.poco-bft.migration.target-genesis-manifest-commitment.v1";

/// Maximum canonical bytes emitted by one target genesis manifest.
pub const MAX_POCO_TARGET_GENESIS_MANIFEST_CANONICAL_BYTES_V1: usize = 2
    + (4 + POCO_TARGET_GENESIS_MANIFEST_PROFILE_V1.len())
    + (2 + crate::MAX_CONSENSUS_STRING_BYTES)
    + 32
    + 32
    + 4
    + 32
    + 32
    + 32;

/// Maximum exact canonical bytes accepted by the target projection decoder.
pub const MAX_POCO_TARGET_PROJECTION_CANONICAL_BYTES_V1: usize = 2
    + (4 + POCO_TARGET_PROJECTION_PROFILE_V1.len())
    + 32
    + 32
    + (2 + crate::MAX_CONSENSUS_STRING_BYTES)
    + 32
    + 32
    + 32;

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
        encoder.u16(COMET_BLOCK_IDENTITY_SCHEMA_VERSION_V1);
        encoder.bytes(COMET_FINALIZED_BLOCK_IDENTITY_PROFILE_V1);
        encoder.fixed(&self.block_hash);
        encoder.u32(self.part_set_total);
        encoder.fixed(&self.part_set_hash);
    }
}

/// A legacy Comet AppHash attestation. It is intentionally distinct from a
/// native PoCO `StateRoot`; the old value can be recorded and signed but can
/// never be passed as the new application root by type substitution. The v1
/// exporter contract must separately freeze whether the source value is
/// exactly 32 bytes or is a documented digest (for example SHA-256); this
/// shape does not truncate, pad, or convert a source AppHash.
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

/// Read-only, content-addressed evidence exported from a finalized legacy
/// Comet application. This is a manifest shape, not a reader for Comet's
/// blockstore or SQLite files. Every digest is an opaque commitment until the
/// source exporter and the independent importer verify its documented
/// preimage; no field authorizes a node or imports validator signing state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CometStateExportV1 {
    source_chain_id: ChainId,
    source_genesis_document_digest: LegacyCometGenesisHashV1,
    source_application_id: [u8; 32],
    source_store_id: [u8; 32],
    finalized_height: Height,
    finalized_block_identity: CometFinalizedBlockIdentityV1,
    source_finality_proof_digest: [u8; 32],
    legacy_app_hash: LegacyCometAppHashV1,
    exported_object_root: [u8; 32],
    exported_index_root: [u8; 32],
    exported_receipts_root: [u8; 32],
    rejected_objects_root: [u8; 32],
    source_validator_set_digest: [u8; 32],
    source_application_schema_digest: [u8; 32],
    source_runtime_profile_digest: [u8; 32],
    mapping_profile_digest: [u8; 32],
}

/// Importer-owned verification boundary for a legacy-state export.
///
/// An implementation MUST independently obtain and verify the exact source
/// preimages before returning `Ok(())`:
///
/// * `verify_source_identity_v1` checks the canonical Comet genesis document,
///   source chain/application/store identities, and the source validator and
///   runtime profile coordinates;
/// * `verify_source_finality_v1` parses and cryptographically verifies the
///   source finality proof at the exact exported height and Comet BlockID,
///   then checks its digest against `source_finality_proof_digest`; and
/// * `verify_mapping_v1` independently replays the export projection and
///   checks the object/index/receipt/rejected roots and mapping profile digest.
///
/// The trait deliberately has no default implementation and receives the
/// complete typed export for every check.  A no-op implementation is therefore
/// not a protocol verifier; callers must provide the audited source reader and
/// proof verifier appropriate for the deployed migration.  This boundary
/// authenticates no target genesis and does not enable activation by itself.
pub trait CometStateExportVerifierV1 {
    fn verify_source_identity_v1(&self, export: &CometStateExportV1) -> Result<()>;

    fn verify_source_finality_v1(&self, export: &CometStateExportV1) -> Result<()>;

    fn verify_mapping_v1(&self, export: &CometStateExportV1) -> Result<()>;
}

/// Type-state token returned only after all three importer-owned source checks
/// have succeeded for one exact `CometStateExportV1` commitment.
///
/// This token is intentionally not convertible to `PocoGenesisV1`, a
/// `GenesisQcV0`, or an activation capability.  The target-state replay and
/// GenesisQC ceremony remain separate gates.  Keeping the original export in
/// the token lets later migration stages bind their own mapping/root proof to
/// the exact bytes that were verified here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCometStateExportV1 {
    export: CometStateExportV1,
    export_commitment: [u8; 32],
}

impl VerifiedCometStateExportV1 {
    pub const fn export(&self) -> &CometStateExportV1 {
        &self.export
    }

    pub const fn export_commitment(&self) -> [u8; 32] {
        self.export_commitment
    }

    /// Consume the token while retaining its source-verification type state.
    /// No target genesis or consensus object is created by this operation.
    pub fn into_export(self) -> CometStateExportV1 {
        self.export
    }

    /// Build a target projection statement from this verified source token.
    /// There is intentionally no equivalent constructor taking a raw
    /// `CometStateExportV1`; the target statement must retain source
    /// identity/finality/mapping type state before a root verifier can run.
    pub fn bind_target_projection_v1(
        &self,
        target_chain_id: ChainId,
        target_genesis_hash: GenesisHash,
        target_genesis_manifest_digest: [u8; 32],
        claimed_state_root: StateRoot,
    ) -> Result<PocoTargetProjectionV1> {
        let projection = PocoTargetProjectionV1 {
            source_export_commitment: self.export_commitment,
            mapping_profile_digest: self.export.mapping_profile_digest(),
            target_chain_id,
            target_genesis_hash,
            target_genesis_manifest_digest,
            claimed_state_root,
        };
        projection.validate_against_verified_source(self)?;
        Ok(projection)
    }

    /// Build a target projection from a typed target-manifest preimage.
    ///
    /// Unlike [`Self::bind_target_projection_v1`], this entry point computes
    /// the manifest commitment and carries the manifest's target/root context
    /// directly into the projection.  It still performs no source mapping or
    /// JMT replay; those remain the explicit [`PocoTargetProjectionV1::verify_with_manifest_v1`]
    /// gate.
    pub fn bind_target_projection_from_manifest_v1(
        &self,
        manifest: &PocoTargetGenesisManifestV1,
    ) -> Result<PocoTargetProjectionV1> {
        let projection = PocoTargetProjectionV1 {
            source_export_commitment: self.export_commitment,
            mapping_profile_digest: self.export.mapping_profile_digest(),
            target_chain_id: manifest.target_chain_id(),
            target_genesis_hash: manifest.target_genesis_hash(),
            target_genesis_manifest_digest: manifest.commitment_digest_v1()?,
            claimed_state_root: manifest.initial_state_root(),
        };
        projection.validate_against_verified_source(self)?;
        Ok(projection)
    }
}

/// Typed, inert preimage for the target genesis manifest referenced by a
/// migration projection.
///
/// The manifest commits the target identity, validator-set/protocol context,
/// application schema/runtime profiles, and the expected initial native state
/// root.  It is deliberately only a canonical preimage and commitment API:
/// it does not read a manifest file, replay JMT, start a node, or authorize
/// activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PocoTargetGenesisManifestV1 {
    target_chain_id: ChainId,
    target_genesis_hash: GenesisHash,
    target_validator_set_digest: ValidatorSetId,
    target_protocol_version: ProtocolVersion,
    application_schema_digest: [u8; 32],
    runtime_profile_digest: [u8; 32],
    initial_state_root: StateRoot,
}

impl PocoTargetGenesisManifestV1 {
    /// Construct one shape-valid target manifest preimage.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_chain_id: ChainId,
        target_genesis_hash: GenesisHash,
        target_validator_set_digest: ValidatorSetId,
        target_protocol_version: ProtocolVersion,
        application_schema_digest: [u8; 32],
        runtime_profile_digest: [u8; 32],
        initial_state_root: StateRoot,
    ) -> Result<Self> {
        if target_genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        if target_validator_set_digest.is_zero() {
            return Err(ValidationError::ValidatorSetMismatch);
        }
        if target_protocol_version != ProtocolVersion::V0 {
            return Err(ValidationError::ProtocolVersionMismatch);
        }
        if application_schema_digest == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "target application schema digest must be nonzero",
            ));
        }
        if runtime_profile_digest == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "target runtime profile digest must be nonzero",
            ));
        }
        if initial_state_root.is_zero() {
            return Err(ValidationError::InvalidCertificate(
                "target manifest initial state root must be nonzero",
            ));
        }
        Ok(Self {
            target_chain_id,
            target_genesis_hash,
            target_validator_set_digest,
            target_protocol_version,
            application_schema_digest,
            runtime_profile_digest,
            initial_state_root,
        })
    }

    pub const fn target_chain_id(&self) -> ChainId {
        self.target_chain_id
    }

    pub const fn target_genesis_hash(&self) -> GenesisHash {
        self.target_genesis_hash
    }

    pub const fn target_validator_set_digest(&self) -> ValidatorSetId {
        self.target_validator_set_digest
    }

    pub const fn target_protocol_version(&self) -> ProtocolVersion {
        self.target_protocol_version
    }

    pub const fn application_schema_digest(&self) -> [u8; 32] {
        self.application_schema_digest
    }

    pub const fn runtime_profile_digest(&self) -> [u8; 32] {
        self.runtime_profile_digest
    }

    /// The expected initial native root carried by this manifest.  This is a
    /// context value, not an independently verified JMT computation.
    pub const fn initial_state_root(&self) -> StateRoot {
        self.initial_state_root
    }

    /// Alias spelling used by projection callers that treat the root as
    /// context until the importer-owned replay verifier recomputes it.
    pub const fn state_root_context(&self) -> StateRoot {
        self.initial_state_root
    }

    /// Exact canonical preimage used for cross-peer manifest comparison.
    pub fn try_canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| {
            encoder.u16(POCO_TARGET_GENESIS_MANIFEST_SCHEMA_VERSION_V1);
            encoder.bytes(POCO_TARGET_GENESIS_MANIFEST_PROFILE_V1);
            encoder.consensus_string(self.target_chain_id.as_bytes());
            encoder.fixed(self.target_genesis_hash.as_bytes());
            encoder.fixed(self.target_validator_set_digest.as_bytes());
            encoder.u32(self.target_protocol_version.get());
            encoder.fixed(&self.application_schema_digest);
            encoder.fixed(&self.runtime_profile_digest);
            encoder.fixed(self.initial_state_root.as_bytes());
        })
    }

    /// Content address of the exact target manifest preimage.
    pub fn commitment_digest_v1(&self) -> Result<[u8; 32]> {
        let bytes = self.try_canonical_bytes_v1()?;
        if bytes.len() > MAX_POCO_TARGET_GENESIS_MANIFEST_CANONICAL_BYTES_V1 {
            return Err(ValidationError::LengthOverflow {
                field: "PocoTargetGenesisManifestV1 canonical bytes",
                actual: bytes.len(),
                maximum: MAX_POCO_TARGET_GENESIS_MANIFEST_CANONICAL_BYTES_V1,
            });
        }
        Ok(hash_len_framed(
            POCO_TARGET_GENESIS_MANIFEST_COMMITMENT_DOMAIN_V1,
            &[&bytes],
        ))
    }

    /// Check that this exact preimage is the manifest commitment referenced by
    /// a projection and that all target/root context fields agree.
    pub fn validate_against_projection_v1(
        &self,
        projection: &PocoTargetProjectionV1,
    ) -> Result<()> {
        if self.commitment_digest_v1()? != projection.target_genesis_manifest_digest()
            || self.target_chain_id != projection.target_chain_id()
            || self.target_genesis_hash != projection.target_genesis_hash()
            || self.initial_state_root != projection.claimed_state_root()
        {
            return Err(ValidationError::ConsensusContextMismatch);
        }
        Ok(())
    }
}

/// A target projection statement assembled only from a verified source
/// export.  The statement binds the source commitment and mapping profile to
/// a fresh target chain, target genesis manifest, and a *claimed* native state
/// root. The claim is not trusted until an importer-owned verifier recomputes
/// the root. It contains no legacy AppHash field: the old value remains
/// confined to [`CometStateExportV1`] as provenance only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoTargetProjectionV1 {
    source_export_commitment: [u8; 32],
    mapping_profile_digest: [u8; 32],
    target_chain_id: ChainId,
    target_genesis_hash: GenesisHash,
    // The canonical target-manifest preimage includes validator-set, protocol,
    // application-schema/runtime and initial-root coordinates.  The projection
    // carries only its commitment on the legacy-compatible shape; callers that
    // have the typed preimage must use `verify_with_manifest_v1`.
    target_genesis_manifest_digest: [u8; 32],
    claimed_state_root: StateRoot,
}

/// Importer-owned verification boundary for a target projection.
///
/// Implementations must obtain the exact target-manifest preimage identified
/// by `target_genesis_manifest_digest` (or let the caller use
/// [`PocoTargetProjectionV1::verify_with_manifest_v1`] with the typed
/// [`PocoTargetGenesisManifestV1`]), independently replay the verified source
/// through the frozen mapping, and recompute the native JMT/state root.
/// The recomputation method deliberately does **not** receive the statement's
/// claimed root, so an implementation cannot merely echo that value. A
/// caller-supplied root or legacy AppHash comparison is not a substitute.
/// The trait has no default implementation so an inert/no-op implementation
/// cannot accidentally be mistaken for a production verifier.
pub trait PocoTargetProjectionVerifierV1 {
    fn verify_target_manifest_v1(
        &self,
        source: &VerifiedCometStateExportV1,
        target_chain_id: ChainId,
        target_genesis_hash: GenesisHash,
        target_genesis_manifest_digest: [u8; 32],
        mapping_profile_digest: [u8; 32],
    ) -> Result<()>;

    /// Typed-preimage variant used by
    /// [`PocoTargetProjectionV1::verify_with_manifest_v1`]. Implementations
    /// may override this method to validate application-schema/runtime fields
    /// directly. The default preserves existing verifiers while ensuring the
    /// commitment supplied to the legacy digest verifier is recomputed from
    /// the exact typed manifest bytes.
    fn verify_target_manifest_preimage_v1(
        &self,
        source: &VerifiedCometStateExportV1,
        manifest: &PocoTargetGenesisManifestV1,
        mapping_profile_digest: [u8; 32],
    ) -> Result<()> {
        self.verify_target_manifest_v1(
            source,
            manifest.target_chain_id(),
            manifest.target_genesis_hash(),
            manifest.commitment_digest_v1()?,
            mapping_profile_digest,
        )
    }

    fn recompute_native_state_root_v1(
        &self,
        source: &VerifiedCometStateExportV1,
        target_chain_id: ChainId,
        target_genesis_hash: GenesisHash,
        target_genesis_manifest_digest: [u8; 32],
        mapping_profile_digest: [u8; 32],
    ) -> Result<StateRoot>;
}

/// Stronger target replay boundary for a typed target-genesis manifest.
///
/// The digest-only [`PocoTargetProjectionVerifierV1`] callback is retained
/// for projections whose manifest preimage is not available yet.  Once an
/// importer has the exact manifest, however, a root replay must receive the
/// complete typed context (validator-set, protocol, application-schema,
/// runtime profile and expected initial-root coordinates).  Requiring this
/// separate trait keeps a digest-only implementation from being silently
/// reused for the manifest path and makes the context available to an
/// independent JMT replay implementation.
pub trait PocoTargetProjectionManifestVerifierV1: PocoTargetProjectionVerifierV1 {
    fn recompute_native_state_root_from_manifest_v1(
        &self,
        source: &VerifiedCometStateExportV1,
        manifest: &PocoTargetGenesisManifestV1,
        mapping_profile_digest: [u8; 32],
    ) -> Result<StateRoot>;
}

/// Type-state token returned only after target-manifest verification and an
/// exact native-root recomputation have succeeded for one verified source.
/// It is intentionally not convertible to `PocoGenesisV1`, `GenesisQcV0`, or
/// any activation capability; quorum and cross-peer ceremony remain separate
/// gates.  The complete verified source export is retained internally so a
/// later GenesisQC composition can bind descriptor source metadata, not only
/// its content-addressed export digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPocoTargetProjectionV1 {
    projection: PocoTargetProjectionV1,
    projection_commitment: [u8; 32],
    /// Retain the complete source-verification token so a later GenesisQC
    /// composition can recheck every source field copied into its descriptor,
    /// rather than trusting only the export commitment carried by the
    /// projection statement.
    source_export: VerifiedCometStateExportV1,
}

impl VerifiedPocoTargetProjectionV1 {
    pub const fn projection(&self) -> &PocoTargetProjectionV1 {
        &self.projection
    }

    pub const fn projection_commitment(&self) -> [u8; 32] {
        self.projection_commitment
    }
}

/// Inert type-state joining one independently verified target projection to
/// one cryptographically verified target-validator genesis ceremony.
///
/// This closes only the composition boundary: the ceremony descriptor must
/// carry the exact verified source-export commitment, mapping profile, target
/// manifest, target genesis identity, and recomputed native state root.  The
/// token is not a `GenesisQcV0`, consensus anchor, startup capability, or
/// production activation authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPocoTargetGenesisCeremonyV1 {
    projection: VerifiedPocoTargetProjectionV1,
    evidence: GenesisQcCeremonyEvidenceV1,
    projection_commitment: [u8; 32],
    evidence_commitment: [u8; 32],
}

impl VerifiedPocoTargetGenesisCeremonyV1 {
    pub const fn projection(&self) -> &VerifiedPocoTargetProjectionV1 {
        &self.projection
    }

    pub const fn evidence(&self) -> &GenesisQcCeremonyEvidenceV1 {
        &self.evidence
    }

    pub const fn projection_commitment(&self) -> [u8; 32] {
        self.projection_commitment
    }

    pub const fn evidence_commitment(&self) -> [u8; 32] {
        self.evidence_commitment
    }
}

impl PocoTargetProjectionV1 {
    pub const fn source_export_commitment(&self) -> [u8; 32] {
        self.source_export_commitment
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

    pub const fn claimed_state_root(&self) -> StateRoot {
        self.claimed_state_root
    }

    /// Rechecks the source type-state binding without invoking a target
    /// verifier. This is a structural check only, not a root proof.
    pub fn validate_against_verified_source(
        &self,
        source: &VerifiedCometStateExportV1,
    ) -> Result<()> {
        if self.source_export_commitment != source.export_commitment()
            || self.mapping_profile_digest != source.export().mapping_profile_digest()
            || self.target_chain_id == source.export().source_chain_id()
        {
            return Err(ValidationError::ConsensusContextMismatch);
        }
        if self.target_genesis_manifest_digest == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "target genesis manifest digest must be nonzero",
            ));
        }
        if self.mapping_profile_digest == [0; 32] {
            return Err(ValidationError::InvalidCertificate(
                "target mapping profile digest must be nonzero",
            ));
        }
        if self.target_genesis_hash.is_zero() {
            return Err(ValidationError::ZeroGenesisHash);
        }
        if self.claimed_state_root.is_zero() {
            return Err(ValidationError::InvalidCertificate(
                "claimed native target state root must be nonzero",
            ));
        }
        if self.claimed_state_root.as_bytes() == source.export().legacy_app_hash().as_bytes() {
            return Err(ValidationError::InvalidCertificate(
                "native target state root must not reuse legacy Comet AppHash",
            ));
        }
        Ok(())
    }

    /// Exact canonical bytes for independent import/replay tooling.
    pub fn try_canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| {
            encoder.u16(POCO_TARGET_PROJECTION_SCHEMA_VERSION_V1);
            encoder.bytes(POCO_TARGET_PROJECTION_PROFILE_V1);
            encoder.fixed(&self.source_export_commitment);
            encoder.fixed(&self.mapping_profile_digest);
            encoder.consensus_string(self.target_chain_id.as_bytes());
            encoder.fixed(self.target_genesis_hash.as_bytes());
            encoder.fixed(&self.target_genesis_manifest_digest);
            encoder.fixed(self.claimed_state_root.as_bytes());
        })
    }

    /// Content address of the exact target projection statement.
    pub fn commitment_digest_v1(&self) -> Result<[u8; 32]> {
        let bytes = self.try_canonical_bytes_v1()?;
        Ok(hash_len_framed(
            POCO_TARGET_PROJECTION_COMMITMENT_DOMAIN_V1,
            &[&bytes],
        ))
    }

    /// Verify this statement against a verified source token and an explicit
    /// importer-owned target replay implementation. The returned token is
    /// still inert and cannot activate a chain.
    pub fn verify_with<V: PocoTargetProjectionVerifierV1>(
        &self,
        source: &VerifiedCometStateExportV1,
        verifier: &V,
    ) -> Result<VerifiedPocoTargetProjectionV1> {
        self.verify_with_context_v1(source, verifier, None, |verifier, source, projection, _| {
            verifier.recompute_native_state_root_v1(
                source,
                projection.target_chain_id,
                projection.target_genesis_hash,
                projection.target_genesis_manifest_digest,
                projection.mapping_profile_digest,
            )
        })
    }

    fn verify_with_context_v1<V, F>(
        &self,
        source: &VerifiedCometStateExportV1,
        verifier: &V,
        manifest: Option<&PocoTargetGenesisManifestV1>,
        recompute: F,
    ) -> Result<VerifiedPocoTargetProjectionV1>
    where
        V: PocoTargetProjectionVerifierV1,
        F: FnOnce(
            &V,
            &VerifiedCometStateExportV1,
            &PocoTargetProjectionV1,
            Option<&PocoTargetGenesisManifestV1>,
        ) -> Result<StateRoot>,
    {
        let canonical = self.try_canonical_bytes_v1()?;
        if canonical.len() > MAX_POCO_TARGET_PROJECTION_CANONICAL_BYTES_V1 {
            return Err(ValidationError::LengthOverflow {
                field: "PocoTargetProjectionV1 canonical bytes",
                actual: canonical.len(),
                maximum: MAX_POCO_TARGET_PROJECTION_CANONICAL_BYTES_V1,
            });
        }
        self.validate_against_verified_source(source)?;
        match manifest {
            Some(manifest) => verifier.verify_target_manifest_preimage_v1(
                source,
                manifest,
                self.mapping_profile_digest,
            )?,
            None => verifier.verify_target_manifest_v1(
                source,
                self.target_chain_id,
                self.target_genesis_hash,
                self.target_genesis_manifest_digest,
                self.mapping_profile_digest,
            )?,
        }
        let recomputed = recompute(verifier, source, self, manifest)?;
        if recomputed.is_zero() || recomputed != self.claimed_state_root {
            return Err(ValidationError::InvalidCertificate(
                "recomputed native target state root does not match statement",
            ));
        }
        Ok(VerifiedPocoTargetProjectionV1 {
            projection: self.clone(),
            projection_commitment: self.commitment_digest_v1()?,
            source_export: source.clone(),
        })
    }

    /// Verify this projection against the exact typed target-manifest
    /// preimage before invoking the importer-owned replay verifier. The typed
    /// verifier callback is dispatched directly; a verifier that overrides
    /// `verify_target_manifest_preimage_v1` therefore cannot be silently
    /// bypassed through the legacy digest-only callback.
    ///
    /// This is the preferred migration boundary once a manifest reader is
    /// available: a digest-only projection cannot silently be paired with a
    /// different validator-set, protocol, application-schema, runtime, or
    /// initial-root context.  The returned token remains inert and does not
    /// authorize JMT activation or node startup.
    pub fn verify_with_manifest_v1<V: PocoTargetProjectionManifestVerifierV1>(
        &self,
        source: &VerifiedCometStateExportV1,
        manifest: &PocoTargetGenesisManifestV1,
        verifier: &V,
    ) -> Result<VerifiedPocoTargetProjectionV1> {
        manifest.validate_against_projection_v1(self)?;
        self.verify_with_context_v1(
            source,
            verifier,
            Some(manifest),
            |verifier, source, projection, manifest| {
                let manifest = manifest.ok_or(ValidationError::InvalidCertificate(
                    "typed target manifest context was not supplied",
                ))?;
                verifier.recompute_native_state_root_from_manifest_v1(
                    source,
                    manifest,
                    projection.mapping_profile_digest,
                )
            },
        )
    }
}

impl CometStateExportV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_chain_id: ChainId,
        source_genesis_document_digest: LegacyCometGenesisHashV1,
        source_application_id: [u8; 32],
        source_store_id: [u8; 32],
        finalized_height: Height,
        finalized_block_identity: CometFinalizedBlockIdentityV1,
        source_finality_proof_digest: [u8; 32],
        legacy_app_hash: LegacyCometAppHashV1,
        exported_object_root: [u8; 32],
        exported_index_root: [u8; 32],
        exported_receipts_root: [u8; 32],
        rejected_objects_root: [u8; 32],
        source_validator_set_digest: [u8; 32],
        source_application_schema_digest: [u8; 32],
        source_runtime_profile_digest: [u8; 32],
        mapping_profile_digest: [u8; 32],
    ) -> Result<Self> {
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
        if finalized_height.get() == 0 {
            return Err(ValidationError::InvalidCertificate(
                "export finalized height must be nonzero",
            ));
        }
        let digest_fields = [
            source_finality_proof_digest,
            exported_object_root,
            exported_index_root,
            exported_receipts_root,
            rejected_objects_root,
            source_validator_set_digest,
            source_application_schema_digest,
            source_runtime_profile_digest,
            mapping_profile_digest,
        ];
        if digest_fields.contains(&[0; 32]) {
            return Err(ValidationError::InvalidCertificate(
                "source export digest fields must be nonzero",
            ));
        }
        Ok(Self {
            source_chain_id,
            source_genesis_document_digest,
            source_application_id,
            source_store_id,
            finalized_height,
            finalized_block_identity,
            source_finality_proof_digest,
            legacy_app_hash,
            exported_object_root,
            exported_index_root,
            exported_receipts_root,
            rejected_objects_root,
            source_validator_set_digest,
            source_application_schema_digest,
            source_runtime_profile_digest,
            mapping_profile_digest,
        })
    }

    pub const fn source_chain_id(&self) -> ChainId {
        self.source_chain_id
    }

    pub const fn source_genesis_document_digest(&self) -> &LegacyCometGenesisHashV1 {
        &self.source_genesis_document_digest
    }

    pub const fn source_application_id(&self) -> [u8; 32] {
        self.source_application_id
    }

    pub const fn source_store_id(&self) -> [u8; 32] {
        self.source_store_id
    }

    pub const fn finalized_height(&self) -> Height {
        self.finalized_height
    }

    pub const fn finalized_block_identity(&self) -> &CometFinalizedBlockIdentityV1 {
        &self.finalized_block_identity
    }

    pub const fn source_finality_proof_digest(&self) -> [u8; 32] {
        self.source_finality_proof_digest
    }

    pub const fn legacy_app_hash(&self) -> &LegacyCometAppHashV1 {
        &self.legacy_app_hash
    }

    pub const fn exported_object_root(&self) -> [u8; 32] {
        self.exported_object_root
    }

    pub const fn exported_index_root(&self) -> [u8; 32] {
        self.exported_index_root
    }

    pub const fn exported_receipts_root(&self) -> [u8; 32] {
        self.exported_receipts_root
    }

    pub const fn rejected_objects_root(&self) -> [u8; 32] {
        self.rejected_objects_root
    }

    pub const fn source_validator_set_digest(&self) -> [u8; 32] {
        self.source_validator_set_digest
    }

    pub const fn source_application_schema_digest(&self) -> [u8; 32] {
        self.source_application_schema_digest
    }

    pub const fn source_runtime_profile_digest(&self) -> [u8; 32] {
        self.source_runtime_profile_digest
    }

    pub const fn mapping_profile_digest(&self) -> [u8; 32] {
        self.mapping_profile_digest
    }

    pub fn try_canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        try_canonical_bytes(|encoder| self.encode_canonical_v1(encoder))
    }

    pub fn commitment_digest_v1(&self) -> Result<[u8; 32]> {
        let bytes = self.try_canonical_bytes_v1()?;
        Ok(hash_len_framed(
            COMET_STATE_EXPORT_COMMITMENT_DOMAIN_V1,
            &[&bytes],
        ))
    }

    /// Run the explicit source identity/finality/mapping verification gate.
    ///
    /// The returned token is the only value in this crate that represents a
    /// verified source export.  This method still does not verify the target
    /// state-root recomputation or any target-validator quorum.  In
    /// particular, [`PocoGenesisV1::new_from_unverified_export_v1`] remains a
    /// shape/commitment constructor and must not be used as an activation
    /// proof.
    pub fn verify_with<V: CometStateExportVerifierV1>(
        &self,
        verifier: &V,
    ) -> Result<VerifiedCometStateExportV1> {
        let canonical = self.try_canonical_bytes_v1()?;
        if canonical.len() > MAX_COMET_STATE_EXPORT_CANONICAL_BYTES_V1 {
            return Err(ValidationError::LengthOverflow {
                field: "CometStateExportV1 canonical bytes",
                actual: canonical.len(),
                maximum: MAX_COMET_STATE_EXPORT_CANONICAL_BYTES_V1,
            });
        }
        let export_commitment = self.commitment_digest_v1()?;

        // Keep the calls separate and ordered.  A caller cannot accidentally
        // treat a source-identity check as a finality or mapping proof.
        verifier.verify_source_identity_v1(self)?;
        verifier.verify_source_finality_v1(self)?;
        verifier.verify_mapping_v1(self)?;

        Ok(VerifiedCometStateExportV1 {
            export: self.clone(),
            export_commitment,
        })
    }

    /// Checks the source-side fields that a `PocoGenesisV1` descriptor copies
    /// directly. It intentionally does not claim that opaque export/finality
    /// digests have been cryptographically verified.
    pub fn validate_against_genesis(&self, descriptor: &PocoGenesisV1) -> Result<()> {
        if self.source_chain_id != descriptor.source_chain_id()
            || self.source_genesis_document_digest != *descriptor.source_genesis_hash()
            || self.source_application_id != descriptor.source_application_id()
            || self.source_store_id != descriptor.source_store_id()
            || self.finalized_height != descriptor.source_height()
            || self.finalized_block_identity != *descriptor.source_block_identity()
            || self.source_finality_proof_digest != descriptor.source_finality_proof_digest()
            || self.legacy_app_hash != *descriptor.legacy_app_hash_attestation()
            || self.mapping_profile_digest != descriptor.mapping_profile_digest()
        {
            return Err(ValidationError::ConsensusContextMismatch);
        }
        if self.commitment_digest_v1()? != descriptor.export_manifest_digest() {
            return Err(ValidationError::ConsensusContextMismatch);
        }
        Ok(())
    }

    fn encode_canonical_v1(&self, encoder: &mut Encoder) {
        encoder.u16(COMET_STATE_EXPORT_SCHEMA_VERSION_V1);
        encoder.bytes(COMET_STATE_EXPORT_PROFILE_V1);
        encoder.consensus_string(self.source_chain_id.as_bytes());
        encoder.fixed(self.source_genesis_document_digest.as_bytes());
        encoder.fixed(&self.source_application_id);
        encoder.fixed(&self.source_store_id);
        encoder.u64(self.finalized_height.get());
        self.finalized_block_identity.encode_canonical_v1(encoder);
        encoder.fixed(&self.source_finality_proof_digest);
        encoder.fixed(self.legacy_app_hash.as_bytes());
        encoder.fixed(&self.exported_object_root);
        encoder.fixed(&self.exported_index_root);
        encoder.fixed(&self.exported_receipts_root);
        encoder.fixed(&self.rejected_objects_root);
        encoder.fixed(&self.source_validator_set_digest);
        encoder.fixed(&self.source_application_schema_digest);
        encoder.fixed(&self.source_runtime_profile_digest);
        encoder.fixed(&self.mapping_profile_digest);
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

    /// Assemble a migration descriptor from the exact typed source export.
    ///
    /// This is a **shape/commitment-only** boundary. The export commitment is
    /// computed from canonical bytes rather than accepted as an operator
    /// supplied digest, and copied source fields are rechecked before the
    /// descriptor is returned. It does not verify the source finality proof,
    /// export roots, mapping preimages, or target state-root recomputation;
    /// activation must require a future verified-export/GenesisQC ceremony
    /// result instead of calling this constructor directly.
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_unverified_export_v1(
        export: &CometStateExportV1,
        target_chain_id: ChainId,
        target_genesis_hash: GenesisHash,
        target_genesis_manifest_digest: [u8; 32],
        new_state_root: StateRoot,
        target_validator_set_digest: ValidatorSetId,
        target_protocol_version: ProtocolVersion,
    ) -> Result<Self> {
        let export_manifest_digest = export.commitment_digest_v1()?;
        let descriptor = Self::new(
            export.source_chain_id(),
            *export.source_genesis_document_digest(),
            export.source_application_id(),
            export.source_store_id(),
            export.finalized_height(),
            *export.finalized_block_identity(),
            export.source_finality_proof_digest(),
            *export.legacy_app_hash(),
            export_manifest_digest,
            export.mapping_profile_digest(),
            target_chain_id,
            target_genesis_hash,
            target_genesis_manifest_digest,
            new_state_root,
            target_validator_set_digest,
            target_protocol_version,
        )?;
        export.validate_against_genesis(&descriptor)?;
        Ok(descriptor)
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

/// One target-validator signature in the additive genesis ceremony evidence.
///
/// The signature bytes have the same fixed width as a CEV0 Ed25519 signature,
/// but this wrapper deliberately prevents accidental substitution into an
/// ordinary QC or handoff certificate. The signature's domain and statement
/// are supplied by [`GenesisQcCeremonyEvidenceV1::signing_root_v1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisQcSignatureShareV1 {
    validator_id: ValidatorId,
    signature: Signature64,
}

impl GenesisQcSignatureShareV1 {
    pub fn new(validator_id: ValidatorId, signature: Signature64) -> Result<Self> {
        signature.validate_shape()?;
        Ok(Self {
            validator_id,
            signature,
        })
    }

    pub const fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    pub const fn signature(&self) -> &Signature64 {
        &self.signature
    }

    fn encode_canonical_v1(&self, encoder: &mut Encoder) {
        encoder.bytes(self.validator_id.as_bytes());
        encoder.fixed(self.signature.as_bytes());
    }
}

/// Inert, target-validator quorum evidence for one exact migration ceremony.
///
/// This type is intentionally *not* a `GenesisQcV0`, ordinary
/// `QuorumCertificate`, or activation authorization. It carries a canonical
/// [`PocoGenesisQcBindingV1`] and an ordered set of target-validator shares so
/// independent peers can recompute one evidence digest and weighted quorum.
/// Source Comet finality, export roots, mapping preimages and target JMT
/// recomputation remain outside this type. No method converts this value into
/// a live consensus anchor or enables production activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisQcCeremonyEvidenceV1 {
    binding: PocoGenesisQcBindingV1,
    signatures: Vec<GenesisQcSignatureShareV1>,
}

impl GenesisQcCeremonyEvidenceV1 {
    /// Constructs shape-valid evidence. Trusted-set membership and quorum are
    /// checked by [`Self::validate_against_trusted_set`], and cryptographic
    /// validity is a separate explicit [`Self::verify`] operation.
    pub fn new(
        binding: PocoGenesisQcBindingV1,
        signatures: Vec<GenesisQcSignatureShareV1>,
    ) -> Result<Self> {
        if signatures.is_empty() {
            return Err(ValidationError::InvalidCertificate(
                "genesis ceremony evidence must contain signatures",
            ));
        }
        if signatures.len() > MAX_GENESIS_QC_CEREMONY_SIGNATURES_V1 {
            return Err(ValidationError::TooManyValidators {
                actual: signatures.len(),
                maximum: MAX_GENESIS_QC_CEREMONY_SIGNATURES_V1,
            });
        }
        let mut previous = None;
        for share in &signatures {
            share.signature.validate_shape()?;
            if let Some(previous) = previous {
                if previous == share.validator_id {
                    return Err(ValidationError::DuplicateSigner(Box::new(
                        share.validator_id,
                    )));
                }
                if previous > share.validator_id {
                    return Err(ValidationError::NonCanonicalSignerOrder);
                }
            }
            previous = Some(share.validator_id);
        }
        Ok(Self {
            binding,
            signatures,
        })
    }

    pub const fn binding(&self) -> &PocoGenesisQcBindingV1 {
        &self.binding
    }

    pub fn signatures(&self) -> &[GenesisQcSignatureShareV1] {
        &self.signatures
    }

    /// The exact statement digest all target validators sign. Share ordering
    /// is deliberately absent, so a valid signature cannot be replayed as a
    /// vote for a different subset or ordinary certificate domain.
    pub fn statement_digest_v1(&self) -> Result<[u8; 32]> {
        self.binding.ceremony_digest_v1()
    }

    /// Computes the distinct v1 signing root for the target genesis quorum.
    /// The synthetic epoch/view/height coordinates are fixed at zero and are
    /// not accepted as ordinary block/QC coordinates.
    pub fn signing_root_v1(&self) -> Result<SigningRoot> {
        let statement = self.statement_digest_v1()?;
        let descriptor = self.binding.descriptor_v1();
        Ok(signing_root(
            GENESIS_QC_CEREMONY_SIGNING_DOMAIN_V1,
            |encoder| {
                encoder.u16(GENESIS_QC_CEREMONY_SCHEMA_VERSION_V1);
                encoder.bytes(GENESIS_QC_CEREMONY_PROFILE_V1);
                encoder.fixed(&statement);
                encoder.consensus_string(descriptor.target_chain_id().as_bytes());
                encoder.fixed(descriptor.target_genesis_hash().as_bytes());
                encoder.fixed(descriptor.target_validator_set_digest().as_bytes());
                encoder.u32(descriptor.target_protocol_version().get());
                encoder.u64(0); // synthetic genesis epoch
                encoder.u64(0); // synthetic genesis view
                encoder.u64(0); // synthetic genesis height
                encoder.u8(GENESIS_QC_CEREMONY_TARGET_ROLE_V1);
            },
        ))
    }

    /// Rechecks target context, signer membership/order and weighted quorum
    /// against the importer-owned validator set. This does not verify
    /// Ed25519 signatures or any source export/finality preimage.
    pub fn validate_against_trusted_set(&self, trusted_set: &ValidatorSet) -> Result<()> {
        self.binding.validate_against_trusted_set(trusted_set)?;
        let mut signed_power = 0u128;
        for share in &self.signatures {
            let power = trusted_set
                .power_of(share.validator_id)
                .ok_or_else(|| ValidationError::UnknownValidator(Box::new(share.validator_id)))?;
            signed_power =
                signed_power
                    .checked_add(power)
                    .ok_or(ValidationError::ArithmeticOverflow(
                        "genesis ceremony signed power",
                    ))?;
        }
        if signed_power < trusted_set.quorum_power() {
            return Err(ValidationError::InsufficientQuorum {
                signed: signed_power,
                required: trusted_set.quorum_power(),
            });
        }
        Ok(())
    }

    /// Explicit cryptographic verification boundary. Production callers must
    /// supply the strict Ed25519 verifier; this crate does not attest which
    /// verifier implementation was used and never turns success into an
    /// activation authorization.
    pub fn verify<V: SignatureVerifier>(
        &self,
        trusted_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<()> {
        self.validate_against_trusted_set(trusted_set)?;
        let signing_root = self.signing_root_v1()?;
        for share in &self.signatures {
            let validator = trusted_set
                .validator(share.validator_id)
                .ok_or_else(|| ValidationError::UnknownValidator(Box::new(share.validator_id)))?;
            if !verifier.verify(validator, &signing_root, &share.signature) {
                return Err(ValidationError::InvalidSignature(Box::new(
                    share.validator_id,
                )));
            }
        }
        Ok(())
    }

    /// Canonical bytes for cross-peer evidence exchange. The binding bytes
    /// already contain the descriptor and frozen empty GenesisQC v0; this
    /// envelope adds only the ordered target quorum shares.
    pub fn try_canonical_bytes_v1(&self) -> Result<Vec<u8>> {
        let binding = self.binding.try_canonical_bytes_v1()?;
        try_canonical_bytes(|encoder| {
            encoder.u16(GENESIS_QC_CEREMONY_SCHEMA_VERSION_V1);
            encoder.bytes(GENESIS_QC_CEREMONY_PROFILE_V1);
            encoder.bytes(&binding);
            encoder.list_len(self.signatures.len());
            for share in &self.signatures {
                share.encode_canonical_v1(encoder);
            }
        })
    }

    /// Content address of the complete evidence envelope. Peers compare this
    /// digest only after exact bytes, trusted-set context and (where enabled)
    /// explicit cryptographic verification all succeed.
    pub fn commitment_digest_v1(&self) -> Result<[u8; 32]> {
        let bytes = self.try_canonical_bytes_v1()?;
        Ok(hash_len_framed(
            GENESIS_QC_CEREMONY_COMMITMENT_DOMAIN_V1,
            &[&bytes],
        ))
    }

    /// Verify the target-validator quorum and bind it to one independently
    /// verified target projection.
    ///
    /// The ordinary [`Self::verify`] method proves only the ceremony evidence
    /// against the trusted validator set.  This stronger composition seam
    /// additionally rejects a descriptor whose source export, mapping,
    /// target-manifest, target genesis identity, or native root differs from
    /// the verified projection.  The returned token remains inert and grants
    /// no startup or activation authority.
    pub fn verify_against_target_projection_v1<V: SignatureVerifier>(
        &self,
        projection: &VerifiedPocoTargetProjectionV1,
        trusted_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<VerifiedPocoTargetGenesisCeremonyV1> {
        let statement = projection.projection();
        let descriptor = self.binding.descriptor_v1();
        // The projection token retains the exact source export that passed
        // identity/finality/mapping verification.  Recheck the complete set
        // of source coordinates copied into the signed descriptor before
        // accepting its target GenesisQC ceremony.  Matching only the export
        // digest would permit a descriptor to pair that digest with forged
        // source metadata (height, BlockID, AppHash, etc.).
        if projection.source_export.export_commitment() != statement.source_export_commitment() {
            return Err(ValidationError::ConsensusContextMismatch);
        }
        projection
            .source_export
            .export()
            .validate_against_genesis(descriptor)?;
        if descriptor.export_manifest_digest() != statement.source_export_commitment()
            || descriptor.mapping_profile_digest() != statement.mapping_profile_digest()
            || descriptor.target_chain_id() != statement.target_chain_id()
            || descriptor.target_genesis_hash() != statement.target_genesis_hash()
            || descriptor.target_genesis_manifest_digest()
                != statement.target_genesis_manifest_digest()
            || descriptor.new_state_root() != statement.claimed_state_root()
        {
            return Err(ValidationError::ConsensusContextMismatch);
        }

        let projection_commitment = statement.commitment_digest_v1()?;
        if projection_commitment != projection.projection_commitment() {
            return Err(ValidationError::ConsensusContextMismatch);
        }

        self.verify(trusted_set, verifier)?;
        Ok(VerifiedPocoTargetGenesisCeremonyV1 {
            projection: projection.clone(),
            evidence: self.clone(),
            projection_commitment,
            evidence_commitment: self.commitment_digest_v1()?,
        })
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
    use core::cell::Cell;

    use super::*;
    use crate::{ChainId, Validator};

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

    fn trusted_set_two() -> ValidatorSet {
        ValidatorSet::new(
            GenesisHash::new([0xA5; 32]),
            CHAIN,
            ProtocolVersion::V0,
            crate::Epoch::new(0),
            crate::ConsensusParametersHash::new([0xC1; 32]),
            vec![
                crate::Validator::new(
                    crate::ValidatorId::from_bytes(b"validator-a").unwrap(),
                    crate::ConsensusPublicKey::new([0xD1; 32]),
                    crate::VotingPower::new(1).unwrap(),
                )
                .unwrap(),
                crate::Validator::new(
                    crate::ValidatorId::from_bytes(b"validator-b").unwrap(),
                    crate::ConsensusPublicKey::new([0xD2; 32]),
                    crate::VotingPower::new(1).unwrap(),
                )
                .unwrap(),
            ],
        )
        .expect("two-validator epoch-zero validator set")
    }

    fn ceremony_evidence(set: &ValidatorSet) -> GenesisQcCeremonyEvidenceV1 {
        let descriptor = migration_descriptor_for_set(set);
        let qc = GenesisQcV0::new(set.genesis_hash(), set.chain_id(), set).unwrap();
        let binding = descriptor
            .bind_genesis_qc_v1_with_trusted_set(qc, set)
            .expect("trusted set-bound ceremony");
        let share = GenesisQcSignatureShareV1::new(
            set.validators()[0].id(),
            Signature64::from_array([0xA1; SIGNATURE_BYTES]),
        )
        .unwrap();
        GenesisQcCeremonyEvidenceV1::new(binding, vec![share])
            .expect("shape-valid target quorum evidence")
    }

    struct AcceptAllGenesisCeremonySignatures;

    impl SignatureVerifier for AcceptAllGenesisCeremonySignatures {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &SigningRoot,
            _signature: &Signature64,
        ) -> bool {
            true
        }
    }

    struct RejectGenesisCeremonySignatures;

    impl SignatureVerifier for RejectGenesisCeremonySignatures {
        fn verify(
            &self,
            _validator: &Validator,
            _signing_root: &SigningRoot,
            _signature: &Signature64,
        ) -> bool {
            false
        }
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

    fn state_export() -> CometStateExportV1 {
        CometStateExportV1::new(
            ChainId::from_static("trnm-source-chain-0"),
            LegacyCometGenesisHashV1::new([0x09; 32]).unwrap(),
            [0x11; 32],
            [0x22; 32],
            Height::new(77),
            CometFinalizedBlockIdentityV1::new([0x33; 32], 1, [0x34; 32]).unwrap(),
            [0x35; 32],
            LegacyCometAppHashV1::new([0x44; 32]).unwrap(),
            [0x51; 32],
            [0x52; 32],
            [0x53; 32],
            [0x54; 32],
            [0x55; 32],
            [0x56; 32],
            [0x57; 32],
            [0x58; 32],
        )
        .expect("shape-valid source export")
    }

    struct RecordingSourceExportVerifier {
        calls: Cell<u8>,
        reject_finality: bool,
    }

    impl CometStateExportVerifierV1 for RecordingSourceExportVerifier {
        fn verify_source_identity_v1(&self, export: &CometStateExportV1) -> Result<()> {
            assert_eq!(
                export.source_chain_id(),
                ChainId::from_static("trnm-source-chain-0")
            );
            self.calls.set(self.calls.get() | 0b001);
            Ok(())
        }

        fn verify_source_finality_v1(&self, export: &CometStateExportV1) -> Result<()> {
            assert_eq!(export.finalized_height(), Height::new(77));
            self.calls.set(self.calls.get() | 0b010);
            if self.reject_finality {
                return Err(ValidationError::InvalidFinalityProof(
                    "test source finality verifier rejected proof",
                ));
            }
            Ok(())
        }

        fn verify_mapping_v1(&self, export: &CometStateExportV1) -> Result<()> {
            assert_eq!(export.mapping_profile_digest(), [0x58; 32]);
            self.calls.set(self.calls.get() | 0b100);
            Ok(())
        }
    }

    #[test]
    fn verified_source_export_requires_identity_finality_and_mapping_gates() {
        let export = state_export();
        let verifier = RecordingSourceExportVerifier {
            calls: Cell::new(0),
            reject_finality: false,
        };
        let verified = export
            .verify_with(&verifier)
            .expect("all explicit source gates pass");
        assert_eq!(verifier.calls.get(), 0b111);
        assert_eq!(verified.export(), &export);
        assert_eq!(
            verified.export_commitment(),
            export.commitment_digest_v1().unwrap()
        );
        assert_eq!(verified.into_export(), export);
    }

    #[test]
    fn verified_source_export_fails_closed_before_mapping_after_finality_rejection() {
        let export = state_export();
        let verifier = RecordingSourceExportVerifier {
            calls: Cell::new(0),
            reject_finality: true,
        };
        assert_eq!(
            export.verify_with(&verifier).unwrap_err(),
            ValidationError::InvalidFinalityProof("test source finality verifier rejected proof")
        );
        assert_eq!(verifier.calls.get(), 0b011);
    }

    fn verified_source_export() -> VerifiedCometStateExportV1 {
        let verifier = RecordingSourceExportVerifier {
            calls: Cell::new(0),
            reject_finality: false,
        };
        state_export()
            .verify_with(&verifier)
            .expect("verified source export")
    }

    struct RecordingTargetProjectionVerifier {
        calls: Cell<u8>,
        reject_manifest: bool,
        recomputed_root: StateRoot,
    }

    impl PocoTargetProjectionVerifierV1 for RecordingTargetProjectionVerifier {
        fn verify_target_manifest_v1(
            &self,
            source: &VerifiedCometStateExportV1,
            target_chain_id: ChainId,
            target_genesis_hash: GenesisHash,
            target_genesis_manifest_digest: [u8; 32],
            mapping_profile_digest: [u8; 32],
        ) -> Result<()> {
            assert_eq!(target_chain_id, ChainId::from_static("trnm-target-chain-0"));
            assert_eq!(target_genesis_hash, GenesisHash::new([0x71; 32]));
            assert_eq!(target_genesis_manifest_digest, [0x72; 32]);
            assert_eq!(mapping_profile_digest, [0x58; 32]);
            assert_ne!(source.export_commitment(), [0; 32]);
            self.calls.set(self.calls.get() | 0b001);
            if self.reject_manifest {
                return Err(ValidationError::InvalidCertificate(
                    "test target manifest verifier rejected manifest",
                ));
            }
            Ok(())
        }

        fn recompute_native_state_root_v1(
            &self,
            _source: &VerifiedCometStateExportV1,
            target_chain_id: ChainId,
            target_genesis_hash: GenesisHash,
            target_genesis_manifest_digest: [u8; 32],
            mapping_profile_digest: [u8; 32],
        ) -> Result<StateRoot> {
            assert_eq!(target_chain_id, ChainId::from_static("trnm-target-chain-0"));
            assert_eq!(target_genesis_hash, GenesisHash::new([0x71; 32]));
            assert_eq!(target_genesis_manifest_digest, [0x72; 32]);
            assert_eq!(mapping_profile_digest, [0x58; 32]);
            self.calls.set(self.calls.get() | 0b010);
            Ok(self.recomputed_root)
        }
    }

    struct RecordingTypedTargetProjectionVerifier {
        typed_calls: Cell<u8>,
        legacy_calls: Cell<u8>,
        root_calls: Cell<u8>,
        expected_validator_set_digest: ValidatorSetId,
        recomputed_root: StateRoot,
        reject_typed: bool,
    }

    impl PocoTargetProjectionVerifierV1 for RecordingTypedTargetProjectionVerifier {
        fn verify_target_manifest_v1(
            &self,
            _source: &VerifiedCometStateExportV1,
            _target_chain_id: ChainId,
            _target_genesis_hash: GenesisHash,
            _target_genesis_manifest_digest: [u8; 32],
            _mapping_profile_digest: [u8; 32],
        ) -> Result<()> {
            self.legacy_calls.set(self.legacy_calls.get() + 1);
            Err(ValidationError::InvalidCertificate(
                "legacy target manifest callback must not run for typed preimage",
            ))
        }

        fn verify_target_manifest_preimage_v1(
            &self,
            _source: &VerifiedCometStateExportV1,
            manifest: &PocoTargetGenesisManifestV1,
            mapping_profile_digest: [u8; 32],
        ) -> Result<()> {
            self.typed_calls.set(self.typed_calls.get() + 1);
            assert_eq!(
                manifest.target_chain_id(),
                ChainId::from_static("trnm-target-chain-0")
            );
            assert_eq!(manifest.target_genesis_hash(), GenesisHash::new([0x71; 32]));
            assert_eq!(
                manifest.target_validator_set_digest(),
                self.expected_validator_set_digest
            );
            assert_eq!(manifest.target_protocol_version(), ProtocolVersion::V0);
            assert_eq!(manifest.application_schema_digest(), [0x75; 32]);
            assert_eq!(manifest.runtime_profile_digest(), [0x76; 32]);
            assert_eq!(manifest.initial_state_root(), StateRoot::new([0x73; 32]));
            assert_eq!(mapping_profile_digest, [0x58; 32]);
            if self.reject_typed {
                return Err(ValidationError::InvalidCertificate(
                    "typed target manifest verifier rejected manifest",
                ));
            }
            Ok(())
        }

        fn recompute_native_state_root_v1(
            &self,
            _source: &VerifiedCometStateExportV1,
            _target_chain_id: ChainId,
            _target_genesis_hash: GenesisHash,
            _target_genesis_manifest_digest: [u8; 32],
            _mapping_profile_digest: [u8; 32],
        ) -> Result<StateRoot> {
            self.root_calls.set(self.root_calls.get() + 1);
            Ok(self.recomputed_root)
        }
    }

    impl PocoTargetProjectionManifestVerifierV1 for RecordingTypedTargetProjectionVerifier {
        fn recompute_native_state_root_from_manifest_v1(
            &self,
            _source: &VerifiedCometStateExportV1,
            manifest: &PocoTargetGenesisManifestV1,
            mapping_profile_digest: [u8; 32],
        ) -> Result<StateRoot> {
            self.root_calls.set(self.root_calls.get() + 1);
            assert_eq!(
                manifest.target_validator_set_digest(),
                self.expected_validator_set_digest
            );
            assert_eq!(manifest.target_protocol_version(), ProtocolVersion::V0);
            assert_eq!(manifest.application_schema_digest(), [0x75; 32]);
            assert_eq!(manifest.runtime_profile_digest(), [0x76; 32]);
            assert_eq!(manifest.initial_state_root(), StateRoot::new([0x73; 32]));
            assert_eq!(mapping_profile_digest, [0x58; 32]);
            Ok(self.recomputed_root)
        }
    }

    fn target_projection_trusted_set() -> ValidatorSet {
        ValidatorSet::new(
            GenesisHash::new([0x71; 32]),
            ChainId::from_static("trnm-target-chain-0"),
            ProtocolVersion::V0,
            crate::Epoch::new(0),
            crate::ConsensusParametersHash::new([0xC2; 32]),
            vec![crate::Validator::new(
                crate::ValidatorId::from_bytes(b"target-validator-a").unwrap(),
                crate::ConsensusPublicKey::new([0xD3; 32]),
                crate::VotingPower::new(1).unwrap(),
            )
            .unwrap()],
        )
        .expect("target projection trusted set")
    }

    fn target_genesis_manifest(trusted_set: &ValidatorSet) -> PocoTargetGenesisManifestV1 {
        PocoTargetGenesisManifestV1::new(
            trusted_set.chain_id(),
            trusted_set.genesis_hash(),
            trusted_set.id(),
            trusted_set.protocol_version(),
            [0x75; 32],
            [0x76; 32],
            StateRoot::new([0x73; 32]),
        )
        .expect("shape-valid target genesis manifest")
    }

    fn descriptor_for_target_projection(
        source: &VerifiedCometStateExportV1,
        projection: &VerifiedPocoTargetProjectionV1,
        trusted_set: &ValidatorSet,
        new_state_root: StateRoot,
    ) -> PocoGenesisV1 {
        let export = source.export();
        let statement = projection.projection();
        PocoGenesisV1::new(
            export.source_chain_id(),
            *export.source_genesis_document_digest(),
            export.source_application_id(),
            export.source_store_id(),
            export.finalized_height(),
            *export.finalized_block_identity(),
            export.source_finality_proof_digest(),
            *export.legacy_app_hash(),
            source.export_commitment(),
            export.mapping_profile_digest(),
            statement.target_chain_id(),
            statement.target_genesis_hash(),
            statement.target_genesis_manifest_digest(),
            new_state_root,
            trusted_set.id(),
            trusted_set.protocol_version(),
        )
        .expect("projection-bound migration descriptor")
    }

    fn ceremony_for_descriptor(
        descriptor: PocoGenesisV1,
        trusted_set: &ValidatorSet,
    ) -> GenesisQcCeremonyEvidenceV1 {
        let qc = GenesisQcV0::new(
            trusted_set.genesis_hash(),
            trusted_set.chain_id(),
            trusted_set,
        )
        .unwrap();
        let binding = descriptor
            .bind_genesis_qc_v1_with_trusted_set(qc, trusted_set)
            .unwrap();
        let share = GenesisQcSignatureShareV1::new(
            trusted_set.validators()[0].id(),
            Signature64::from_array([0xA2; SIGNATURE_BYTES]),
        )
        .unwrap();
        GenesisQcCeremonyEvidenceV1::new(binding, vec![share]).unwrap()
    }

    fn ceremony_for_target_projection(
        source: &VerifiedCometStateExportV1,
        projection: &VerifiedPocoTargetProjectionV1,
        trusted_set: &ValidatorSet,
        new_state_root: StateRoot,
    ) -> GenesisQcCeremonyEvidenceV1 {
        let descriptor =
            descriptor_for_target_projection(source, projection, trusted_set, new_state_root);
        ceremony_for_descriptor(descriptor, trusted_set)
    }

    #[test]
    fn target_projection_is_bound_to_verified_source_and_recomputed_root() {
        let source = verified_source_export();
        let projection = source
            .bind_target_projection_v1(
                ChainId::from_static("trnm-target-chain-0"),
                GenesisHash::new([0x71; 32]),
                [0x72; 32],
                StateRoot::new([0x73; 32]),
            )
            .expect("target projection shape");
        let verifier = RecordingTargetProjectionVerifier {
            calls: Cell::new(0),
            reject_manifest: false,
            recomputed_root: StateRoot::new([0x73; 32]),
        };
        let verified = projection
            .verify_with(&source, &verifier)
            .expect("target manifest and root replay pass");
        assert_eq!(verifier.calls.get(), 0b011);
        assert_eq!(verified.projection(), &projection);
        assert_eq!(
            verified.projection_commitment(),
            projection.commitment_digest_v1().unwrap()
        );
        assert_ne!(
            projection.claimed_state_root().as_bytes(),
            source.export().legacy_app_hash().as_bytes()
        );
    }

    #[test]
    fn target_projection_fails_closed_on_manifest_or_root_mismatch() {
        let source = verified_source_export();
        let projection = source
            .bind_target_projection_v1(
                ChainId::from_static("trnm-target-chain-0"),
                GenesisHash::new([0x71; 32]),
                [0x72; 32],
                StateRoot::new([0x73; 32]),
            )
            .unwrap();
        let manifest_rejected = RecordingTargetProjectionVerifier {
            calls: Cell::new(0),
            reject_manifest: true,
            recomputed_root: StateRoot::new([0x73; 32]),
        };
        assert_eq!(
            projection
                .verify_with(&source, &manifest_rejected)
                .unwrap_err(),
            ValidationError::InvalidCertificate("test target manifest verifier rejected manifest")
        );
        assert_eq!(manifest_rejected.calls.get(), 0b001);

        let root_mismatch = RecordingTargetProjectionVerifier {
            calls: Cell::new(0),
            reject_manifest: false,
            recomputed_root: StateRoot::new([0x74; 32]),
        };
        assert!(matches!(
            projection.verify_with(&source, &root_mismatch),
            Err(ValidationError::InvalidCertificate(
                "recomputed native target state root does not match statement"
            ))
        ));
        assert_eq!(root_mismatch.calls.get(), 0b011);
    }

    #[test]
    fn typed_target_manifest_verifier_dispatches_and_fails_closed() {
        let source = verified_source_export();
        let trusted_set = target_projection_trusted_set();
        let manifest = target_genesis_manifest(&trusted_set);
        let projection = source
            .bind_target_projection_from_manifest_v1(&manifest)
            .expect("typed target manifest projection");

        let verifier = RecordingTypedTargetProjectionVerifier {
            typed_calls: Cell::new(0),
            legacy_calls: Cell::new(0),
            root_calls: Cell::new(0),
            expected_validator_set_digest: trusted_set.id(),
            recomputed_root: StateRoot::new([0x73; 32]),
            reject_typed: false,
        };
        projection
            .verify_with_manifest_v1(&source, &manifest, &verifier)
            .expect("typed target manifest and root replay pass");
        assert_eq!(verifier.typed_calls.get(), 1);
        assert_eq!(verifier.legacy_calls.get(), 0);
        assert_eq!(verifier.root_calls.get(), 1);

        let rejecting = RecordingTypedTargetProjectionVerifier {
            typed_calls: Cell::new(0),
            legacy_calls: Cell::new(0),
            root_calls: Cell::new(0),
            expected_validator_set_digest: trusted_set.id(),
            recomputed_root: StateRoot::new([0x73; 32]),
            reject_typed: true,
        };
        assert_eq!(
            projection
                .verify_with_manifest_v1(&source, &manifest, &rejecting)
                .unwrap_err(),
            ValidationError::InvalidCertificate("typed target manifest verifier rejected manifest")
        );
        assert_eq!(rejecting.typed_calls.get(), 1);
        assert_eq!(rejecting.legacy_calls.get(), 0);
        assert_eq!(rejecting.root_calls.get(), 0);
    }

    #[test]
    fn target_genesis_manifest_decoder_is_exact_and_bounded() {
        let trusted_set = target_projection_trusted_set();
        let manifest = target_genesis_manifest(&trusted_set);
        let bytes = manifest
            .try_canonical_bytes_v1()
            .expect("canonical target manifest bytes");
        assert_eq!(
            crate::decode_poco_target_genesis_manifest_v1_exact(&bytes).unwrap(),
            manifest
        );
        assert_eq!(
            bytes.len(),
            MAX_POCO_TARGET_GENESIS_MANIFEST_CANONICAL_BYTES_V1
                - (crate::MAX_CONSENSUS_STRING_BYTES - trusted_set.chain_id().as_bytes().len())
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            crate::decode_poco_target_genesis_manifest_v1_exact(&trailing)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::TrailingBytes
        );

        let mut wrong_schema = bytes.clone();
        wrong_schema[1] = 2;
        assert_eq!(
            crate::decode_poco_target_genesis_manifest_v1_exact(&wrong_schema)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::InvalidSchemaVersion
        );

        let mut wrong_profile = bytes.clone();
        wrong_profile[6] ^= 1;
        assert_eq!(
            crate::decode_poco_target_genesis_manifest_v1_exact(&wrong_profile)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::ContextMismatch
        );

        let oversized = vec![0; MAX_POCO_TARGET_GENESIS_MANIFEST_CANONICAL_BYTES_V1 + 1];
        assert_eq!(
            crate::decode_poco_target_genesis_manifest_v1_exact(&oversized)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::LengthLimitExceeded
        );
    }

    #[test]
    fn target_genesis_ceremony_binds_exact_verified_projection_before_quorum_verify() {
        let source = verified_source_export();
        let trusted_set = target_projection_trusted_set();
        let projection = source
            .bind_target_projection_v1(
                trusted_set.chain_id(),
                trusted_set.genesis_hash(),
                [0x72; 32],
                StateRoot::new([0x73; 32]),
            )
            .unwrap()
            .verify_with(
                &source,
                &RecordingTargetProjectionVerifier {
                    calls: Cell::new(0),
                    reject_manifest: false,
                    recomputed_root: StateRoot::new([0x73; 32]),
                },
            )
            .unwrap();
        let evidence = ceremony_for_target_projection(
            &source,
            &projection,
            &trusted_set,
            StateRoot::new([0x73; 32]),
        );

        let verified = evidence
            .verify_against_target_projection_v1(
                &projection,
                &trusted_set,
                &AcceptAllGenesisCeremonySignatures,
            )
            .expect("projection-bound target quorum ceremony");
        assert_eq!(verified.projection(), &projection);
        assert_eq!(verified.evidence(), &evidence);
        assert_eq!(
            verified.projection_commitment(),
            projection.projection_commitment()
        );
        assert_eq!(
            verified.evidence_commitment(),
            evidence.commitment_digest_v1().unwrap()
        );
    }

    #[test]
    fn target_genesis_ceremony_rejects_projection_substitution_and_bad_signature() {
        let source = verified_source_export();
        let trusted_set = target_projection_trusted_set();
        let projection = source
            .bind_target_projection_v1(
                trusted_set.chain_id(),
                trusted_set.genesis_hash(),
                [0x72; 32],
                StateRoot::new([0x73; 32]),
            )
            .unwrap()
            .verify_with(
                &source,
                &RecordingTargetProjectionVerifier {
                    calls: Cell::new(0),
                    reject_manifest: false,
                    recomputed_root: StateRoot::new([0x73; 32]),
                },
            )
            .unwrap();

        let mismatched = ceremony_for_target_projection(
            &source,
            &projection,
            &trusted_set,
            StateRoot::new([0x74; 32]),
        );
        assert_eq!(
            mismatched
                .verify_against_target_projection_v1(
                    &projection,
                    &trusted_set,
                    &AcceptAllGenesisCeremonySignatures,
                )
                .unwrap_err(),
            ValidationError::ConsensusContextMismatch
        );

        let matching = ceremony_for_target_projection(
            &source,
            &projection,
            &trusted_set,
            StateRoot::new([0x73; 32]),
        );
        assert!(matches!(
            matching.verify_against_target_projection_v1(
                &projection,
                &trusted_set,
                &RejectGenesisCeremonySignatures,
            ),
            Err(ValidationError::InvalidSignature(_))
        ));
    }

    #[test]
    fn target_genesis_ceremony_rejects_forged_source_metadata_with_matching_export_digest() {
        let source = verified_source_export();
        let trusted_set = target_projection_trusted_set();
        let projection = source
            .bind_target_projection_v1(
                trusted_set.chain_id(),
                trusted_set.genesis_hash(),
                [0x72; 32],
                StateRoot::new([0x73; 32]),
            )
            .unwrap()
            .verify_with(
                &source,
                &RecordingTargetProjectionVerifier {
                    calls: Cell::new(0),
                    reject_manifest: false,
                    recomputed_root: StateRoot::new([0x73; 32]),
                },
            )
            .unwrap();

        let export = source.export();
        let forged_descriptor = PocoGenesisV1::new(
            ChainId::from_static("trnm-forged-source-chain-0"),
            *export.source_genesis_document_digest(),
            export.source_application_id(),
            export.source_store_id(),
            export.finalized_height(),
            *export.finalized_block_identity(),
            export.source_finality_proof_digest(),
            *export.legacy_app_hash(),
            source.export_commitment(),
            export.mapping_profile_digest(),
            projection.projection().target_chain_id(),
            projection.projection().target_genesis_hash(),
            projection.projection().target_genesis_manifest_digest(),
            projection.projection().claimed_state_root(),
            trusted_set.id(),
            trusted_set.protocol_version(),
        )
        .expect("shape-valid descriptor with forged source metadata");
        let evidence = ceremony_for_descriptor(forged_descriptor, &trusted_set);

        assert_eq!(
            evidence
                .verify_against_target_projection_v1(
                    &projection,
                    &trusted_set,
                    &AcceptAllGenesisCeremonySignatures,
                )
                .unwrap_err(),
            ValidationError::ConsensusContextMismatch
        );
    }

    #[test]
    fn target_projection_rejects_legacy_app_hash_substitution() {
        let source = verified_source_export();
        let legacy_root = StateRoot::new(*source.export().legacy_app_hash().as_bytes());
        assert!(matches!(
            source.bind_target_projection_v1(
                ChainId::from_static("trnm-target-chain-0"),
                GenesisHash::new([0x71; 32]),
                [0x72; 32],
                legacy_root,
            ),
            Err(ValidationError::InvalidCertificate(
                "native target state root must not reuse legacy Comet AppHash"
            ))
        ));
        assert!(matches!(
            source.bind_target_projection_v1(
                ChainId::from_static("trnm-target-chain-0"),
                GenesisHash::new([0; 32]),
                [0x72; 32],
                StateRoot::new([0x73; 32]),
            ),
            Err(ValidationError::ZeroGenesisHash)
        ));
        assert!(matches!(
            source.bind_target_projection_v1(
                ChainId::from_static("trnm-target-chain-0"),
                GenesisHash::new([0x71; 32]),
                [0; 32],
                StateRoot::new([0x73; 32]),
            ),
            Err(ValidationError::InvalidCertificate(
                "target genesis manifest digest must be nonzero"
            ))
        ));
        assert!(matches!(
            source.bind_target_projection_v1(
                ChainId::from_static("trnm-target-chain-0"),
                GenesisHash::new([0x71; 32]),
                [0x72; 32],
                StateRoot::new([0; 32]),
            ),
            Err(ValidationError::InvalidCertificate(
                "claimed native target state root must be nonzero"
            ))
        ));
        assert!(matches!(
            source.bind_target_projection_v1(
                source.export().source_chain_id(),
                GenesisHash::new([0x71; 32]),
                [0x72; 32],
                StateRoot::new([0x73; 32]),
            ),
            Err(ValidationError::ConsensusContextMismatch)
        ));
    }

    #[test]
    fn target_projection_decoder_requires_exact_verified_source_context() {
        let source = verified_source_export();
        let maximum_chain =
            ChainId::from_bytes(&[b'x'; crate::MAX_CONSENSUS_STRING_BYTES]).unwrap();
        let maximum_projection = source
            .bind_target_projection_v1(
                maximum_chain,
                GenesisHash::new([0x79; 32]),
                [0x7A; 32],
                StateRoot::new([0x7B; 32]),
            )
            .unwrap();
        assert_eq!(
            maximum_projection.try_canonical_bytes_v1().unwrap().len(),
            MAX_POCO_TARGET_PROJECTION_CANONICAL_BYTES_V1
        );
        let projection = source
            .bind_target_projection_v1(
                ChainId::from_static("trnm-target-chain-0"),
                GenesisHash::new([0x71; 32]),
                [0x72; 32],
                StateRoot::new([0x73; 32]),
            )
            .unwrap();
        let bytes = projection.try_canonical_bytes_v1().unwrap();
        assert_eq!(
            crate::decode_poco_target_projection_v1_exact(&bytes, &source).unwrap(),
            projection
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            crate::decode_poco_target_projection_v1_exact(&trailing, &source)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::TrailingBytes
        );

        let mut wrong_profile = bytes.clone();
        wrong_profile[6] ^= 1;
        assert_eq!(
            crate::decode_poco_target_projection_v1_exact(&wrong_profile, &source)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::ContextMismatch
        );

        let mut wrong_schema = bytes.clone();
        wrong_schema[1] = 2;
        assert_eq!(
            crate::decode_poco_target_projection_v1_exact(&wrong_schema, &source)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::InvalidSchemaVersion
        );

        let source_commitment_offset = 2 + 4 + POCO_TARGET_PROJECTION_PROFILE_V1.len();
        let mut wrong_source_commitment = bytes.clone();
        wrong_source_commitment[source_commitment_offset] ^= 1;
        assert_eq!(
            crate::decode_poco_target_projection_v1_exact(&wrong_source_commitment, &source)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::ContextMismatch
        );

        let mut wrong_mapping = bytes.clone();
        wrong_mapping[source_commitment_offset + 32] ^= 1;
        assert_eq!(
            crate::decode_poco_target_projection_v1_exact(&wrong_mapping, &source)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::ContextMismatch
        );

        let oversized = vec![0u8; MAX_POCO_TARGET_PROJECTION_CANONICAL_BYTES_V1 + 1];
        assert_eq!(
            crate::decode_poco_target_projection_v1_exact(&oversized, &source)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::LengthLimitExceeded
        );

        let other_export = CometStateExportV1::new(
            source.export().source_chain_id(),
            *source.export().source_genesis_document_digest(),
            [0x12; 32],
            source.export().source_store_id(),
            source.export().finalized_height(),
            *source.export().finalized_block_identity(),
            source.export().source_finality_proof_digest(),
            *source.export().legacy_app_hash(),
            source.export().exported_object_root(),
            source.export().exported_index_root(),
            source.export().exported_receipts_root(),
            source.export().rejected_objects_root(),
            source.export().source_validator_set_digest(),
            source.export().source_application_schema_digest(),
            source.export().source_runtime_profile_digest(),
            source.export().mapping_profile_digest(),
        )
        .unwrap();
        let verifier = RecordingSourceExportVerifier {
            calls: Cell::new(0),
            reject_finality: false,
        };
        let other_source = other_export.verify_with(&verifier).unwrap();
        assert_eq!(
            crate::decode_poco_target_projection_v1_exact(&bytes, &other_source)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::ContextMismatch
        );
    }

    #[test]
    fn comet_state_export_decoder_is_exact_and_profile_bound() {
        let export = state_export();
        let bytes = export.try_canonical_bytes_v1().unwrap();
        assert_eq!(
            crate::decode_comet_state_export_v1_exact(&bytes).unwrap(),
            export
        );
        assert_ne!(export.commitment_digest_v1().unwrap(), [0; 32]);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            crate::decode_comet_state_export_v1_exact(&trailing)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::TrailingBytes
        );

        let mut wrong_profile = bytes;
        wrong_profile[6] ^= 1;
        assert_eq!(
            crate::decode_comet_state_export_v1_exact(&wrong_profile)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::ContextMismatch
        );

        let oversized = vec![0u8; MAX_COMET_STATE_EXPORT_CANONICAL_BYTES_V1 + 1];
        assert_eq!(
            crate::decode_comet_state_export_v1_exact(&oversized)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::LengthLimitExceeded
        );

        let descriptor = PocoGenesisV1::new_from_unverified_export_v1(
            &export,
            CHAIN,
            GenesisHash::new([0x71; 32]),
            [0x72; 32],
            StateRoot::new([0x73; 32]),
            crate::ValidatorSetId::new([0x74; 32]),
            ProtocolVersion::V0,
        )
        .unwrap();
        export
            .validate_against_genesis(&descriptor)
            .expect("export fields match descriptor source");

        let changed_export = CometStateExportV1::new(
            export.source_chain_id(),
            *export.source_genesis_document_digest(),
            export.source_application_id(),
            export.source_store_id(),
            export.finalized_height(),
            *export.finalized_block_identity(),
            export.source_finality_proof_digest(),
            *export.legacy_app_hash(),
            [0x59; 32],
            export.exported_index_root(),
            export.exported_receipts_root(),
            export.rejected_objects_root(),
            export.source_validator_set_digest(),
            export.source_application_schema_digest(),
            export.source_runtime_profile_digest(),
            export.mapping_profile_digest(),
        )
        .unwrap();
        assert!(changed_export
            .validate_against_genesis(&descriptor)
            .is_err());
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
    fn genesis_qc_ceremony_evidence_is_inert_exact_and_explicitly_verified() {
        let set = trusted_set();
        let evidence = ceremony_evidence(&set);
        let bytes = evidence.try_canonical_bytes_v1().unwrap();
        assert_eq!(
            crate::decode_genesis_qc_ceremony_evidence_v1_exact(&bytes, &set).unwrap(),
            evidence
        );
        assert_ne!(evidence.statement_digest_v1().unwrap(), [0; 32]);
        assert_ne!(evidence.commitment_digest_v1().unwrap(), [0; 32]);
        assert_ne!(evidence.signing_root_v1().unwrap().as_bytes(), &[0; 32]);
        evidence
            .validate_against_trusted_set(&set)
            .expect("shape and weighted quorum");
        evidence
            .verify(&set, &AcceptAllGenesisCeremonySignatures)
            .expect("explicit verifier accepts fixture");
        assert!(matches!(
            evidence.verify(&set, &RejectGenesisCeremonySignatures),
            Err(ValidationError::InvalidSignature(_))
        ));

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            crate::decode_genesis_qc_ceremony_evidence_v1_exact(&trailing, &set)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::TrailingBytes
        );
        let mut wrong_profile = bytes.clone();
        wrong_profile[6] ^= 1;
        assert_eq!(
            crate::decode_genesis_qc_ceremony_evidence_v1_exact(&wrong_profile, &set)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::ContextMismatch
        );
        let oversized = vec![0u8; MAX_GENESIS_QC_CEREMONY_CANONICAL_BYTES_V1 + 1];
        assert_eq!(
            crate::decode_genesis_qc_ceremony_evidence_v1_exact(&oversized, &set)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::LengthLimitExceeded
        );
    }

    #[test]
    fn genesis_qc_ceremony_evidence_rejects_below_quorum_and_foreign_set() {
        let two = trusted_set_two();
        let evidence = ceremony_evidence(&two);
        assert_eq!(
            evidence.validate_against_trusted_set(&two).unwrap_err(),
            ValidationError::InsufficientQuorum {
                signed: 1,
                required: 2,
            }
        );
        let bytes = evidence.try_canonical_bytes_v1().unwrap();
        assert_eq!(
            crate::decode_genesis_qc_ceremony_evidence_v1_exact(&bytes, &two)
                .unwrap_err()
                .code(),
            crate::DecodeErrorCode::InsufficientQuorum
        );

        let one = trusted_set();
        assert_eq!(
            crate::decode_genesis_qc_ceremony_evidence_v1_exact(
                &ceremony_evidence(&one)
                    .try_canonical_bytes_v1()
                    .expect("canonical evidence"),
                &two,
            )
            .unwrap_err()
            .code(),
            crate::DecodeErrorCode::ContextMismatch
        );
    }

    #[test]
    fn genesis_qc_ceremony_signing_root_is_subset_independent_but_commitment_is_not() {
        let set = trusted_set();
        let first = ceremony_evidence(&set);
        let binding = first.binding().clone();
        let alternate_share = GenesisQcSignatureShareV1::new(
            set.validators()[0].id(),
            Signature64::from_array([0xA2; SIGNATURE_BYTES]),
        )
        .unwrap();
        let second = GenesisQcCeremonyEvidenceV1::new(binding, vec![alternate_share]).unwrap();
        assert_eq!(
            first.signing_root_v1().unwrap(),
            second.signing_root_v1().unwrap()
        );
        assert_ne!(
            first.commitment_digest_v1().unwrap(),
            second.commitment_digest_v1().unwrap()
        );
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

    #[test]
    fn migration_descriptor_max_width_chain_ids_stay_inside_decoder_cap() {
        let max_chain = ChainId::from_bytes(&[b'x'; crate::MAX_CONSENSUS_STRING_BYTES])
            .expect("maximum admitted chain id");
        let descriptor = PocoGenesisV1::new(
            ChainId::from_static("trnm-source-chain-0"),
            LegacyCometGenesisHashV1::new([0x61; 32]).unwrap(),
            [0x62; 32],
            [0x63; 32],
            Height::new(9),
            CometFinalizedBlockIdentityV1::new([0x64; 32], 1, [0x65; 32]).unwrap(),
            [0x66; 32],
            LegacyCometAppHashV1::new([0x67; 32]).unwrap(),
            [0x68; 32],
            [0x69; 32],
            max_chain,
            GenesisHash::new([0x6A; 32]),
            [0x6B; 32],
            StateRoot::new([0x6C; 32]),
            crate::ValidatorSetId::new([0x6D; 32]),
            ProtocolVersion::V0,
        )
        .unwrap();
        let bytes = descriptor.try_canonical_bytes_v1().unwrap();
        assert!(bytes.len() <= MAX_POCO_GENESIS_CANONICAL_BYTES_V1);
        assert_eq!(
            crate::decode_poco_genesis_v1_exact(&bytes).unwrap(),
            descriptor
        );
    }
}
