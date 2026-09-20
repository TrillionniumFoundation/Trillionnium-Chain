#![forbid(unsafe_code)]
//! Finalized-export to fresh-genesis migration core.
//!
//! This crate intentionally has no database rewrite path and no validator
//! signing-state import API.  It verifies an exact finalized source export,
//! projects rows into a target schema, recomputes the target root through an
//! injected canonical builder, and binds cutover agreement to a no-fallback
//! plan.

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub const MIGRATION_VERSION_V0: u16 = 0;
pub const MAX_EXPORT_ROWS_V0: u64 = 100_000_000;
pub const MAX_NAMESPACE_BYTES_V0: usize = 128;
pub const MAX_KEY_BYTES_V0: usize = 64 * 1024;
pub const MAX_VALUE_BYTES_V0: usize = 16 * 1024 * 1024;
pub const MAX_CUTOVER_SIGNERS_V0: usize = 1024;
/// A delta is deliberately bounded independently from a full export.  Hosts
/// must split larger catch-up work into multiple authenticated deltas rather
/// than allowing one allocation to become an unbounded migration primitive.
pub const MAX_INCREMENTAL_DELTA_ROWS_V0: usize = 1_000_000;

static TEMPORARY_STORE_NONCE_V0: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest32V0(pub [u8; 32]);

impl Digest32V0 {
    #[must_use]
    pub fn hash(domain: &[u8], parts: &[&[u8]]) -> Self {
        let mut h = Sha256::new();
        h.update((domain.len() as u64).to_be_bytes());
        h.update(domain);
        for part in parts {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
        Self(h.finalize().into())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExportRowV0 {
    pub namespace: Vec<u8>,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub row_digest: Digest32V0,
}

impl ExportRowV0 {
    #[must_use]
    pub fn canonical_digest(namespace: &[u8], key: &[u8], value: &[u8]) -> Digest32V0 {
        Digest32V0::hash(b"trnm.migration.export-row.v0", &[namespace, key, value])
    }

    pub fn validate(&self) -> Result<(), MigrationErrorV0> {
        if self.namespace.is_empty()
            || self.namespace.len() > MAX_NAMESPACE_BYTES_V0
            || self.key.is_empty()
            || self.key.len() > MAX_KEY_BYTES_V0
            || self.value.len() > MAX_VALUE_BYTES_V0
            || self.row_digest != Self::canonical_digest(&self.namespace, &self.key, &self.value)
        {
            return Err(MigrationErrorV0::InvalidExportRow);
        }
        if forbidden_authority_namespace(&self.namespace) {
            return Err(MigrationErrorV0::ForbiddenAuthorityState);
        }
        Ok(())
    }
}

#[must_use]
pub fn forbidden_authority_namespace(namespace: &[u8]) -> bool {
    const RESERVED: &[&[u8]] = &[
        b"validator_signing_state",
        b"consensus_private_key",
        b"signer_journal",
        b"safety_store",
        b"remote_signer_watermark",
        b"node_commit_ledger",
        b"operator_recovery_key",
    ];
    RESERVED.iter().any(|prefix| namespace.starts_with(prefix))
}

#[must_use]
pub fn merkle_root_v0(digests: &[Digest32V0]) -> Digest32V0 {
    if digests.is_empty() {
        return Digest32V0::hash(b"trnm.migration.empty-root.v0", &[]);
    }
    let mut level = digests.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(Digest32V0::hash(
                b"trnm.migration.merkle-node.v0",
                &[&left.0, &right.0],
            ));
        }
        level = next;
    }
    level[0]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedExportHeaderV0 {
    pub source_chain_id: Digest32V0,
    pub source_protocol_digest: Digest32V0,
    pub source_height: u64,
    pub source_state_root: Digest32V0,
    pub source_schema_digest: Digest32V0,
    pub source_finality_proof_digest: Digest32V0,
    pub row_count: u64,
    pub export_root: Digest32V0,
    pub header_digest: Digest32V0,
}

impl FinalizedExportHeaderV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.migration.finalized-export-header.v0",
            &[
                &self.source_chain_id.0,
                &self.source_protocol_digest.0,
                &self.source_height.to_be_bytes(),
                &self.source_state_root.0,
                &self.source_schema_digest.0,
                &self.source_finality_proof_digest.0,
                &self.row_count.to_be_bytes(),
                &self.export_root.0,
            ],
        )
    }
}

pub trait SourceFinalityVerifierV0 {
    type Error: Error + Send + Sync + 'static;

    fn verify_finalized_export(&self, header: &FinalizedExportHeaderV0) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Issued only by [`verify_export_v0`].  The fields are intentionally private
/// so a caller cannot manufacture a finalized-source capability from a peer
/// header or a row checksum.
pub struct VerifiedExportV0 {
    header: FinalizedExportHeaderV0,
    ordered_rows_digest: Digest32V0,
}

impl VerifiedExportV0 {
    #[must_use]
    pub const fn header(&self) -> FinalizedExportHeaderV0 {
        self.header
    }

    #[must_use]
    pub const fn ordered_rows_digest(&self) -> Digest32V0 {
        self.ordered_rows_digest
    }
}

/// Immutable capability describing the exact finalized source that was
/// verified before migration projection.  This object carries no signer or
/// cutover authority; it prevents a later projection/store handoff from
/// silently substituting a source height, root, schema, proof or row set.
/// Its fields are private; callers must obtain it from a `VerifiedExportV0`
/// and use `validate_against` before handing it to another adapter.
///
/// ```compile_fail
/// use trnm_migration_v0::FinalizedSourceBindingV0;
/// let _forged = FinalizedSourceBindingV0 {};
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedSourceBindingV0 {
    source_chain_id: Digest32V0,
    source_protocol_digest: Digest32V0,
    source_height: u64,
    source_state_root: Digest32V0,
    source_schema_digest: Digest32V0,
    source_finality_proof_digest: Digest32V0,
    export_header_digest: Digest32V0,
    export_root: Digest32V0,
    ordered_rows_digest: Digest32V0,
    row_count: u64,
    binding_digest: Digest32V0,
}

impl FinalizedSourceBindingV0 {
    #[must_use]
    pub const fn source_chain_id(&self) -> Digest32V0 {
        self.source_chain_id
    }

    #[must_use]
    pub const fn source_protocol_digest(&self) -> Digest32V0 {
        self.source_protocol_digest
    }

    #[must_use]
    pub const fn source_height(&self) -> u64 {
        self.source_height
    }

    #[must_use]
    pub const fn source_state_root(&self) -> Digest32V0 {
        self.source_state_root
    }

    #[must_use]
    pub const fn source_schema_digest(&self) -> Digest32V0 {
        self.source_schema_digest
    }

    #[must_use]
    pub const fn source_finality_proof_digest(&self) -> Digest32V0 {
        self.source_finality_proof_digest
    }

    #[must_use]
    pub const fn export_header_digest(&self) -> Digest32V0 {
        self.export_header_digest
    }

    #[must_use]
    pub const fn export_root(&self) -> Digest32V0 {
        self.export_root
    }

    #[must_use]
    pub const fn ordered_rows_digest(&self) -> Digest32V0 {
        self.ordered_rows_digest
    }

    #[must_use]
    pub const fn row_count(&self) -> u64 {
        self.row_count
    }

    #[must_use]
    pub const fn binding_digest(&self) -> Digest32V0 {
        self.binding_digest
    }

    #[must_use]
    pub fn from_verified_export(export: &VerifiedExportV0) -> Self {
        let header = export.header;
        let mut binding = Self {
            source_chain_id: header.source_chain_id,
            source_protocol_digest: header.source_protocol_digest,
            source_height: header.source_height,
            source_state_root: header.source_state_root,
            source_schema_digest: header.source_schema_digest,
            source_finality_proof_digest: header.source_finality_proof_digest,
            export_header_digest: header.header_digest,
            export_root: header.export_root,
            ordered_rows_digest: export.ordered_rows_digest,
            row_count: header.row_count,
            binding_digest: Digest32V0([0; 32]),
        };
        binding.binding_digest = binding.canonical_digest();
        binding
    }

    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.migration.finalized-source-binding.v0",
            &[
                &self.source_chain_id.0,
                &self.source_protocol_digest.0,
                &self.source_height.to_be_bytes(),
                &self.source_state_root.0,
                &self.source_schema_digest.0,
                &self.source_finality_proof_digest.0,
                &self.export_header_digest.0,
                &self.export_root.0,
                &self.ordered_rows_digest.0,
                &self.row_count.to_be_bytes(),
            ],
        )
    }

    pub fn validate_against(&self, export: &VerifiedExportV0) -> Result<(), MigrationErrorV0> {
        if self.binding_digest == Digest32V0([0; 32])
            || self.binding_digest != self.canonical_digest()
            || *self != Self::from_verified_export(export)
        {
            return Err(MigrationErrorV0::InvalidSourceBinding);
        }
        Ok(())
    }
}

impl VerifiedExportV0 {
    #[must_use]
    pub fn source_binding_v0(&self) -> FinalizedSourceBindingV0 {
        FinalizedSourceBindingV0::from_verified_export(self)
    }
}

fn validate_verified_rows_v0(
    export: &VerifiedExportV0,
    rows: &[ExportRowV0],
) -> Result<(), MigrationErrorV0> {
    if export.header.row_count != rows.len() as u64 {
        return Err(MigrationErrorV0::VerifiedExportMismatch);
    }
    let mut previous: Option<(&[u8], &[u8])> = None;
    let mut row_digests = Vec::with_capacity(rows.len());
    let mut ordered_hasher = Sha256::new();
    ordered_hasher.update(b"trnm.migration.ordered-rows.v0");
    for row in rows {
        row.validate()?;
        if previous.is_some_and(|(namespace, key)| {
            (row.namespace.as_slice(), row.key.as_slice()) <= (namespace, key)
        }) {
            return Err(MigrationErrorV0::RowsNotStrictlyOrdered);
        }
        previous = Some((&row.namespace, &row.key));
        row_digests.push(row.row_digest);
        ordered_hasher.update(row.row_digest.0);
    }
    if merkle_root_v0(&row_digests) != export.header.export_root
        || Digest32V0(ordered_hasher.finalize().into()) != export.ordered_rows_digest
    {
        return Err(MigrationErrorV0::VerifiedExportMismatch);
    }
    Ok(())
}

pub fn verify_export_v0<V>(
    verifier: &V,
    header: FinalizedExportHeaderV0,
    rows: &[ExportRowV0],
) -> Result<VerifiedExportV0, MigrationHostErrorV0<V::Error>>
where
    V: SourceFinalityVerifierV0,
{
    if header.source_chain_id == Digest32V0([0; 32])
        || header.source_protocol_digest == Digest32V0([0; 32])
        || header.source_height == 0
        || header.source_state_root == Digest32V0([0; 32])
        || header.source_schema_digest == Digest32V0([0; 32])
        || header.source_finality_proof_digest == Digest32V0([0; 32])
        || header.row_count == 0
        || header.row_count > MAX_EXPORT_ROWS_V0
        || header.row_count != rows.len() as u64
        || header.export_root == Digest32V0([0; 32])
        || header.header_digest == Digest32V0([0; 32])
        || header.header_digest != header.canonical_digest()
    {
        return Err(MigrationHostErrorV0::Protocol(
            MigrationErrorV0::InvalidExportHeader,
        ));
    }
    verifier
        .verify_finalized_export(&header)
        .map_err(MigrationHostErrorV0::SourceFinality)?;

    let mut previous: Option<(&[u8], &[u8])> = None;
    let mut row_digests = Vec::with_capacity(rows.len());
    let mut ordered_hasher = Sha256::new();
    ordered_hasher.update(b"trnm.migration.ordered-rows.v0");
    for row in rows {
        row.validate().map_err(MigrationHostErrorV0::Protocol)?;
        if previous.is_some_and(|(namespace, key)| {
            (row.namespace.as_slice(), row.key.as_slice()) <= (namespace, key)
        }) {
            return Err(MigrationHostErrorV0::Protocol(
                MigrationErrorV0::RowsNotStrictlyOrdered,
            ));
        }
        previous = Some((&row.namespace, &row.key));
        row_digests.push(row.row_digest);
        ordered_hasher.update(row.row_digest.0);
    }
    if merkle_root_v0(&row_digests) != header.export_root {
        return Err(MigrationHostErrorV0::Protocol(
            MigrationErrorV0::ExportRootMismatch,
        ));
    }
    Ok(VerifiedExportV0 {
        header,
        ordered_rows_digest: Digest32V0(ordered_hasher.finalize().into()),
    })
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TargetRowV0 {
    pub namespace: Vec<u8>,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl TargetRowV0 {
    pub fn validate(&self) -> Result<(), MigrationErrorV0> {
        if self.namespace.is_empty()
            || self.namespace.len() > MAX_NAMESPACE_BYTES_V0
            || self.key.is_empty()
            || self.key.len() > MAX_KEY_BYTES_V0
            || self.value.len() > MAX_VALUE_BYTES_V0
            || forbidden_authority_namespace(&self.namespace)
        {
            return Err(MigrationErrorV0::InvalidTargetRow);
        }
        Ok(())
    }
}

pub trait TargetProjectorV0 {
    type Error: Error + Send + Sync + 'static;

    fn project(&self, source: &ExportRowV0) -> Result<Option<TargetRowV0>, Self::Error>;
}

pub trait TargetRootBuilderV0 {
    type Error: Error + Send + Sync + 'static;

    fn recompute_target_root<'a, I>(
        &self,
        target_schema_digest: Digest32V0,
        rows: I,
    ) -> Result<Digest32V0, Self::Error>
    where
        I: IntoIterator<Item = &'a TargetRowV0>;
}

/// Finalized source/target identity carried by an incremental state delta.
///
/// A row/root pair alone is not a checkpoint.  This context binds the delta
/// to the independently verified chain/protocol, checkpoint block, height,
/// epoch, validator-set and finality-proof identities.  Callers must obtain
/// both values from the M13 trust-path/finality owner; this crate only checks
/// their internal consistency and never treats a peer-supplied context as
/// authenticated by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceCheckpointContextV0 {
    pub chain_id: Digest32V0,
    pub protocol_digest: Digest32V0,
    pub checkpoint_digest: Digest32V0,
    pub block_id: Digest32V0,
    pub height: u64,
    pub epoch: u64,
    pub state_root: Digest32V0,
    pub validator_set_digest: Digest32V0,
    pub finality_proof_digest: Digest32V0,
}

impl SourceCheckpointContextV0 {
    #[must_use]
    pub fn canonical_digest(self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.migration.source-checkpoint-context.v0",
            &[
                &self.chain_id.0,
                &self.protocol_digest.0,
                &self.checkpoint_digest.0,
                &self.block_id.0,
                &self.height.to_be_bytes(),
                &self.epoch.to_be_bytes(),
                &self.state_root.0,
                &self.validator_set_digest.0,
                &self.finality_proof_digest.0,
            ],
        )
    }

    fn validate(self) -> Result<(), MigrationErrorV0> {
        if self.chain_id == Digest32V0([0; 32])
            || self.protocol_digest == Digest32V0([0; 32])
            || self.checkpoint_digest == Digest32V0([0; 32])
            || self.block_id == Digest32V0([0; 32])
            || self.height == 0
            || self.state_root == Digest32V0([0; 32])
            || self.validator_set_digest == Digest32V0([0; 32])
            || self.finality_proof_digest == Digest32V0([0; 32])
            || self.canonical_digest() == Digest32V0([0; 32])
        {
            return Err(MigrationErrorV0::InvalidSourceCheckpointContext);
        }
        Ok(())
    }
}

/// A checkpoint context that has passed an owner-supplied finality/trust-path
/// verifier.  The raw [`SourceCheckpointContextV0`] remains a wire/projection
/// value and therefore is not proof.  This capability is the typed boundary
/// that a node integration must cross before it can derive or install an
/// incremental migration artifact.  Its fields are private so a caller
/// cannot manufacture a verified context by copying peer supplied bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedSourceCheckpointContextV0 {
    context: SourceCheckpointContextV0,
    verification_digest: Digest32V0,
}

impl VerifiedSourceCheckpointContextV0 {
    #[must_use]
    pub const fn context(&self) -> SourceCheckpointContextV0 {
        self.context
    }

    #[must_use]
    pub fn context_digest(&self) -> Digest32V0 {
        self.context.canonical_digest()
    }

    /// A stable identity for the typed verification handoff.  This is not a
    /// substitute for the proof digest inside `context`; it prevents adapters
    /// from accidentally dropping the fact that the owner verification step
    /// was executed before publication.
    #[must_use]
    pub const fn verification_digest(&self) -> Digest32V0 {
        self.verification_digest
    }
}

/// Owner boundary for turning a decoded checkpoint context into a migration
/// capability.  Implementations must perform the real checkpoint/finality
/// verification (including chain, epoch, validator-set and proof binding).
/// This crate deliberately has no consensus verifier dependency and therefore
/// cannot provide a production implementation itself.
pub trait SourceCheckpointContextVerifierV0 {
    type Error: Error + Send + Sync + 'static;

    fn verify_checkpoint_context(
        &self,
        context: &SourceCheckpointContextV0,
    ) -> Result<(), Self::Error>;
}

/// Verify and issue an opaque context capability.  A verifier that merely
/// returns `Ok(())` is suitable only for a fixture; production callers must
/// wire this to the M01/M02/M08 trust path.
pub fn verify_source_checkpoint_context_v0<V>(
    verifier: &V,
    context: SourceCheckpointContextV0,
) -> Result<VerifiedSourceCheckpointContextV0, MigrationHostErrorV0<V::Error>>
where
    V: SourceCheckpointContextVerifierV0,
{
    context.validate().map_err(MigrationHostErrorV0::Protocol)?;
    verifier
        .verify_checkpoint_context(&context)
        .map_err(MigrationHostErrorV0::SourceCheckpointContext)?;
    let verification_digest = Digest32V0::hash(
        b"trnm.migration.verified-source-checkpoint-context.v0",
        &[&context.canonical_digest().0],
    );
    Ok(VerifiedSourceCheckpointContextV0 {
        context,
        verification_digest,
    })
}

/// One canonical key mutation in an incremental target-state delta.
///
/// `value = None` is a deletion; `Some(empty)` is a distinct empty value.  The
/// operation digest commits to that distinction and to the exact namespace/key
/// bytes, so a caller cannot reinterpret a deletion as an insertion while
/// replaying an otherwise valid delta.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TargetDeltaRowV0 {
    pub namespace: Vec<u8>,
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub operation_digest: Digest32V0,
}

impl TargetDeltaRowV0 {
    #[must_use]
    pub fn canonical_digest(namespace: &[u8], key: &[u8], value: Option<&[u8]>) -> Digest32V0 {
        let kind = [u8::from(value.is_some())];
        Digest32V0::hash(
            b"trnm.migration.incremental-delta-row.v0",
            &[namespace, key, &kind, value.unwrap_or_default()],
        )
    }

    pub fn validate(&self) -> Result<(), MigrationErrorV0> {
        if self.namespace.is_empty()
            || self.namespace.len() > MAX_NAMESPACE_BYTES_V0
            || self.key.is_empty()
            || self.key.len() > MAX_KEY_BYTES_V0
            || self
                .value
                .as_ref()
                .is_some_and(|value| value.len() > MAX_VALUE_BYTES_V0)
            || forbidden_authority_namespace(&self.namespace)
            || self.operation_digest
                != Self::canonical_digest(&self.namespace, &self.key, self.value.as_deref())
        {
            return Err(MigrationErrorV0::InvalidDeltaRow);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncrementalStateDeltaV0 {
    pub plan_digest: Digest32V0,
    pub target_schema_digest: Digest32V0,
    pub source_context: SourceCheckpointContextV0,
    pub target_context: SourceCheckpointContextV0,
    pub base_rows_digest: Digest32V0,
    pub base_state_root: Digest32V0,
    pub target_rows_digest: Digest32V0,
    pub target_state_root: Digest32V0,
    pub base_row_count: u64,
    pub target_row_count: u64,
    pub delta_root: Digest32V0,
    pub delta_digest: Digest32V0,
    pub entries: Vec<TargetDeltaRowV0>,
}

impl IncrementalStateDeltaV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.migration.incremental-delta.v0",
            &[
                &self.plan_digest.0,
                &self.target_schema_digest.0,
                &self.source_context.canonical_digest().0,
                &self.target_context.canonical_digest().0,
                &self.base_rows_digest.0,
                &self.base_state_root.0,
                &self.target_rows_digest.0,
                &self.target_state_root.0,
                &self.base_row_count.to_be_bytes(),
                &self.target_row_count.to_be_bytes(),
                &self.delta_root.0,
                &(self.entries.len() as u64).to_be_bytes(),
            ],
        )
    }

    fn validate(&self) -> Result<(), MigrationErrorV0> {
        self.source_context.validate()?;
        self.target_context.validate()?;
        if self.plan_digest == Digest32V0([0; 32])
            || self.target_schema_digest == Digest32V0([0; 32])
            || self.base_rows_digest == Digest32V0([0; 32])
            || self.base_state_root == Digest32V0([0; 32])
            || self.target_rows_digest == Digest32V0([0; 32])
            || self.target_state_root == Digest32V0([0; 32])
            || self.delta_root == Digest32V0([0; 32])
            || self.entries.len() > MAX_INCREMENTAL_DELTA_ROWS_V0
            || self.base_row_count > MAX_EXPORT_ROWS_V0
            || self.target_row_count > MAX_EXPORT_ROWS_V0
            || self.entries.len() as u64 > MAX_INCREMENTAL_DELTA_ROWS_V0 as u64
            || self.delta_digest != self.canonical_digest()
            || self.source_context.chain_id != self.target_context.chain_id
            || self.source_context.protocol_digest != self.target_context.protocol_digest
            || self.target_context.height <= self.source_context.height
            || self.target_context.epoch < self.source_context.epoch
            || self.target_context.epoch > self.source_context.epoch.saturating_add(1)
            || self.source_context.state_root != self.base_state_root
            || self.target_context.state_root != self.target_state_root
        {
            return Err(MigrationErrorV0::InvalidIncrementalDelta);
        }
        let mut previous: Option<(&[u8], &[u8])> = None;
        let mut digests = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            entry.validate()?;
            if previous.is_some_and(|(namespace, key)| {
                (entry.namespace.as_slice(), entry.key.as_slice()) <= (namespace, key)
            }) {
                return Err(MigrationErrorV0::RowsNotStrictlyOrdered);
            }
            previous = Some((&entry.namespace, &entry.key));
            digests.push(entry.operation_digest);
        }
        if incremental_delta_root_v0(&digests) != self.delta_root {
            return Err(MigrationErrorV0::DeltaRootMismatch);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum IncrementalDeltaErrorV0<RootError> {
    Protocol(MigrationErrorV0),
    RootBuilder(RootError),
}

impl<R: fmt::Display> fmt::Display for IncrementalDeltaErrorV0<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "incremental migration delta rejected: {error}"),
            Self::RootBuilder(error) => write!(f, "incremental target root failed: {error}"),
        }
    }
}

impl<R: Error + 'static> Error for IncrementalDeltaErrorV0<R> {}

fn validate_target_rows_v0(rows: &[TargetRowV0]) -> Result<(), MigrationErrorV0> {
    if rows.len() > MAX_EXPORT_ROWS_V0 as usize {
        return Err(MigrationErrorV0::TargetRowsOutOfBounds);
    }
    let mut previous: Option<(&[u8], &[u8])> = None;
    for row in rows {
        row.validate()?;
        if previous.is_some_and(|(namespace, key)| {
            (row.namespace.as_slice(), row.key.as_slice()) <= (namespace, key)
        }) {
            return Err(MigrationErrorV0::RowsNotStrictlyOrdered);
        }
        previous = Some((&row.namespace, &row.key));
    }
    Ok(())
}

fn target_rows_digest_v0(rows: &[TargetRowV0]) -> Digest32V0 {
    let mut digest = Sha256::new();
    digest.update(b"trnm.migration.target-rows.v0");
    for row in rows {
        digest.update(ExportRowV0::canonical_digest(&row.namespace, &row.key, &row.value).0);
    }
    Digest32V0(digest.finalize().into())
}

#[must_use]
pub fn incremental_delta_root_v0(digests: &[Digest32V0]) -> Digest32V0 {
    if digests.is_empty() {
        return Digest32V0::hash(b"trnm.migration.empty-delta-root.v0", &[]);
    }
    let mut level = digests.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            next.push(Digest32V0::hash(
                b"trnm.migration.incremental-delta-node.v0",
                &[&pair[0].0, &right.0],
            ));
        }
        level = next;
    }
    level[0]
}

/// Compute a bounded, authenticated delta between two strictly ordered target
/// states and independently recompute both roots.  This is a pure producer:
/// it writes no database and does not grant cutover or signer authority.
pub fn derive_incremental_delta_v0<R>(
    plan_digest: Digest32V0,
    target_schema_digest: Digest32V0,
    source_context: SourceCheckpointContextV0,
    target_context: SourceCheckpointContextV0,
    base_rows: &[TargetRowV0],
    target_rows: &[TargetRowV0],
    root_builder: &R,
) -> Result<IncrementalStateDeltaV0, IncrementalDeltaErrorV0<R::Error>>
where
    R: TargetRootBuilderV0,
{
    if plan_digest == Digest32V0([0; 32]) || target_schema_digest == Digest32V0([0; 32]) {
        return Err(IncrementalDeltaErrorV0::Protocol(
            MigrationErrorV0::InvalidIncrementalDelta,
        ));
    }
    source_context
        .validate()
        .map_err(IncrementalDeltaErrorV0::Protocol)?;
    target_context
        .validate()
        .map_err(IncrementalDeltaErrorV0::Protocol)?;
    validate_target_rows_v0(base_rows).map_err(IncrementalDeltaErrorV0::Protocol)?;
    validate_target_rows_v0(target_rows).map_err(IncrementalDeltaErrorV0::Protocol)?;
    let base_state_root = root_builder
        .recompute_target_root(target_schema_digest, base_rows.iter())
        .map_err(IncrementalDeltaErrorV0::RootBuilder)?;
    let target_state_root = root_builder
        .recompute_target_root(target_schema_digest, target_rows.iter())
        .map_err(IncrementalDeltaErrorV0::RootBuilder)?;
    if base_state_root == Digest32V0([0; 32]) || target_state_root == Digest32V0([0; 32]) {
        return Err(IncrementalDeltaErrorV0::Protocol(
            MigrationErrorV0::InvalidTargetRoot,
        ));
    }
    if source_context.chain_id != target_context.chain_id
        || source_context.protocol_digest != target_context.protocol_digest
        || target_context.height <= source_context.height
        || target_context.epoch < source_context.epoch
        || target_context.epoch > source_context.epoch.saturating_add(1)
        || source_context.state_root != base_state_root
        || target_context.state_root != target_state_root
    {
        return Err(IncrementalDeltaErrorV0::Protocol(
            MigrationErrorV0::SourceCheckpointContextMismatch,
        ));
    }
    let mut entries = Vec::new();
    let (mut base_index, mut target_index) = (0_usize, 0_usize);
    while base_index < base_rows.len() || target_index < target_rows.len() {
        let next = match (base_rows.get(base_index), target_rows.get(target_index)) {
            (Some(base), Some(target)) => match (
                base.namespace.as_slice(),
                base.key.as_slice(),
                target.namespace.as_slice(),
                target.key.as_slice(),
            ) {
                (bn, bk, tn, tk) if (bn, bk) < (tn, tk) => {
                    base_index += 1;
                    TargetDeltaRowV0 {
                        namespace: bn.to_vec(),
                        key: bk.to_vec(),
                        value: None,
                        operation_digest: Digest32V0([0; 32]),
                    }
                }
                (bn, bk, tn, tk) if (bn, bk) > (tn, tk) => {
                    target_index += 1;
                    TargetDeltaRowV0 {
                        namespace: tn.to_vec(),
                        key: tk.to_vec(),
                        value: Some(target.value.clone()),
                        operation_digest: Digest32V0([0; 32]),
                    }
                }
                _ => {
                    base_index += 1;
                    target_index += 1;
                    if base.value == target.value {
                        continue;
                    }
                    TargetDeltaRowV0 {
                        namespace: target.namespace.clone(),
                        key: target.key.clone(),
                        value: Some(target.value.clone()),
                        operation_digest: Digest32V0([0; 32]),
                    }
                }
            },
            (Some(base), None) => {
                base_index += 1;
                TargetDeltaRowV0 {
                    namespace: base.namespace.clone(),
                    key: base.key.clone(),
                    value: None,
                    operation_digest: Digest32V0([0; 32]),
                }
            }
            (None, Some(target)) => {
                target_index += 1;
                TargetDeltaRowV0 {
                    namespace: target.namespace.clone(),
                    key: target.key.clone(),
                    value: Some(target.value.clone()),
                    operation_digest: Digest32V0([0; 32]),
                }
            }
            (None, None) => unreachable!(),
        };
        if entries.len() == MAX_INCREMENTAL_DELTA_ROWS_V0 {
            return Err(IncrementalDeltaErrorV0::Protocol(
                MigrationErrorV0::DeltaRowsOutOfBounds,
            ));
        }
        let mut next = next;
        next.operation_digest =
            TargetDeltaRowV0::canonical_digest(&next.namespace, &next.key, next.value.as_deref());
        entries.push(next);
    }
    let digests = entries
        .iter()
        .map(|entry| entry.operation_digest)
        .collect::<Vec<_>>();
    let delta_root = incremental_delta_root_v0(&digests);
    let mut delta = IncrementalStateDeltaV0 {
        plan_digest,
        target_schema_digest,
        source_context,
        target_context,
        base_rows_digest: target_rows_digest_v0(base_rows),
        base_state_root,
        target_rows_digest: target_rows_digest_v0(target_rows),
        target_state_root,
        base_row_count: base_rows.len() as u64,
        target_row_count: target_rows.len() as u64,
        delta_root,
        delta_digest: Digest32V0([0; 32]),
        entries,
    };
    delta.delta_digest = delta.canonical_digest();
    Ok(delta)
}

/// Derive a delta only after both checkpoint contexts crossed the opaque
/// owner-verification boundary.  This is the intended node integration API;
/// the raw-context variant remains useful to low-level protocol producers and
/// fixtures but does not claim finality authentication.
pub fn derive_incremental_delta_verified_v0<R>(
    plan_digest: Digest32V0,
    target_schema_digest: Digest32V0,
    source_context: &VerifiedSourceCheckpointContextV0,
    target_context: &VerifiedSourceCheckpointContextV0,
    base_rows: &[TargetRowV0],
    target_rows: &[TargetRowV0],
    root_builder: &R,
) -> Result<IncrementalStateDeltaV0, IncrementalDeltaErrorV0<R::Error>>
where
    R: TargetRootBuilderV0,
{
    derive_incremental_delta_v0(
        plan_digest,
        target_schema_digest,
        source_context.context,
        target_context.context,
        base_rows,
        target_rows,
        root_builder,
    )
}

/// Verify and apply one authenticated delta to an exact base state.  Every
/// key/value and both roots are recomputed before a target vector is returned.
pub fn apply_incremental_delta_v0<R>(
    delta: &IncrementalStateDeltaV0,
    source_context: &SourceCheckpointContextV0,
    target_context: &SourceCheckpointContextV0,
    base_rows: &[TargetRowV0],
    root_builder: &R,
) -> Result<Vec<TargetRowV0>, IncrementalDeltaErrorV0<R::Error>>
where
    R: TargetRootBuilderV0,
{
    delta
        .validate()
        .map_err(IncrementalDeltaErrorV0::Protocol)?;
    if &delta.source_context != source_context || &delta.target_context != target_context {
        return Err(IncrementalDeltaErrorV0::Protocol(
            MigrationErrorV0::SourceCheckpointContextMismatch,
        ));
    }
    validate_target_rows_v0(base_rows).map_err(IncrementalDeltaErrorV0::Protocol)?;
    if base_rows.len() as u64 != delta.base_row_count
        || target_rows_digest_v0(base_rows) != delta.base_rows_digest
        || root_builder
            .recompute_target_root(delta.target_schema_digest, base_rows.iter())
            .map_err(IncrementalDeltaErrorV0::RootBuilder)?
            != delta.base_state_root
    {
        return Err(IncrementalDeltaErrorV0::Protocol(
            MigrationErrorV0::BaseStateMismatch,
        ));
    }
    let mut output = Vec::with_capacity(delta.target_row_count as usize);
    let mut base_index = 0_usize;
    for entry in &delta.entries {
        while let Some(base) = base_rows.get(base_index) {
            let base_key = (base.namespace.as_slice(), base.key.as_slice());
            let entry_key = (entry.namespace.as_slice(), entry.key.as_slice());
            if base_key < entry_key {
                output.push(base.clone());
                base_index += 1;
            } else {
                break;
            }
        }
        if let Some(base) = base_rows.get(base_index) {
            if (base.namespace.as_slice(), base.key.as_slice())
                == (entry.namespace.as_slice(), entry.key.as_slice())
            {
                base_index += 1;
            }
        }
        if let Some(value) = &entry.value {
            output.push(TargetRowV0 {
                namespace: entry.namespace.clone(),
                key: entry.key.clone(),
                value: value.clone(),
            });
        }
    }
    output.extend(base_rows[base_index..].iter().cloned());
    validate_target_rows_v0(&output).map_err(IncrementalDeltaErrorV0::Protocol)?;
    if output.len() as u64 != delta.target_row_count
        || target_rows_digest_v0(&output) != delta.target_rows_digest
        || root_builder
            .recompute_target_root(delta.target_schema_digest, output.iter())
            .map_err(IncrementalDeltaErrorV0::RootBuilder)?
            != delta.target_state_root
    {
        return Err(IncrementalDeltaErrorV0::Protocol(
            MigrationErrorV0::TargetStateMismatch,
        ));
    }
    Ok(output)
}

/// Apply a delta while requiring exact opaque owner-verified source and target
/// contexts.  The durable store still performs its own persisted CAS; this
/// wrapper closes the earlier API gap where a caller could pass an arbitrary
/// context struct to the pure apply function.
pub fn apply_incremental_delta_verified_v0<R>(
    delta: &IncrementalStateDeltaV0,
    source_context: &VerifiedSourceCheckpointContextV0,
    target_context: &VerifiedSourceCheckpointContextV0,
    base_rows: &[TargetRowV0],
    root_builder: &R,
) -> Result<Vec<TargetRowV0>, IncrementalDeltaErrorV0<R::Error>>
where
    R: TargetRootBuilderV0,
{
    apply_incremental_delta_v0(
        delta,
        &source_context.context,
        &target_context.context,
        base_rows,
        root_builder,
    )
}

const DURABLE_STORE_APP_ID_V0: i64 = 0x5452_4d44;
const DURABLE_META_SQL_V0: &str = "CREATE TABLE migration_delta_meta_v0 (singleton INTEGER PRIMARY KEY CHECK(singleton=1), plan_digest BLOB NOT NULL CHECK(length(plan_digest)=32), schema_digest BLOB NOT NULL CHECK(length(schema_digest)=32), source_context_digest BLOB NOT NULL CHECK(length(source_context_digest)=32), target_context_digest BLOB NOT NULL CHECK(length(target_context_digest)=32), rows_digest BLOB NOT NULL CHECK(length(rows_digest)=32), state_root BLOB NOT NULL CHECK(length(state_root)=32), row_count INTEGER NOT NULL CHECK(row_count>=0), generation INTEGER NOT NULL CHECK(generation>=0), last_delta_digest BLOB NOT NULL CHECK(length(last_delta_digest)=32)) STRICT";
const DURABLE_ROWS_SQL_V0: &str = "CREATE TABLE migration_delta_rows_v0 (namespace BLOB NOT NULL, key BLOB NOT NULL, value BLOB NOT NULL, PRIMARY KEY(namespace,key)) WITHOUT ROWID";

/// Durable readback from the bounded SQLite staging adapter.  The rows remain
/// private to the adapter; callers receive them only through `read_rows_v0`,
/// which validates the closed-world ordering and digests again.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableDeltaReadbackV0 {
    pub plan_digest: Digest32V0,
    pub target_schema_digest: Digest32V0,
    pub source_context_digest: Digest32V0,
    pub target_context_digest: Digest32V0,
    pub rows_digest: Digest32V0,
    pub state_root: Digest32V0,
    pub row_count: u64,
    pub generation: u64,
    pub last_delta_digest: Digest32V0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableDeltaInstallReceiptV0 {
    pub previous_root: Digest32V0,
    pub installed_root: Digest32V0,
    pub generation: u64,
    pub delta_digest: Digest32V0,
}

/// A deterministic, authority-free snapshot of one durable incremental-state
/// generation.  The snapshot is suitable for a local staging handoff; it is
/// not a finalized-export proof and cannot authorize a signer or a cutover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableDeltaSnapshotV0 {
    pub plan_digest: Digest32V0,
    pub target_schema_digest: Digest32V0,
    pub source_context_digest: Digest32V0,
    pub target_context_digest: Digest32V0,
    pub rows_digest: Digest32V0,
    pub state_root: Digest32V0,
    pub row_count: u64,
    pub generation: u64,
    pub last_delta_digest: Digest32V0,
    pub rows: Vec<TargetRowV0>,
    pub snapshot_digest: Digest32V0,
}

impl DurableDeltaSnapshotV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.migration.durable-delta-snapshot.v0",
            &[
                &self.plan_digest.0,
                &self.target_schema_digest.0,
                &self.source_context_digest.0,
                &self.target_context_digest.0,
                &self.rows_digest.0,
                &self.state_root.0,
                &self.row_count.to_be_bytes(),
                &self.generation.to_be_bytes(),
                &self.last_delta_digest.0,
            ],
        )
    }

    fn validate<R>(&self, root_builder: &R) -> Result<(), DurableDeltaStoreErrorV0>
    where
        R: TargetRootBuilderV0,
        R::Error: fmt::Display,
    {
        if self.plan_digest == Digest32V0([0; 32])
            || self.target_schema_digest == Digest32V0([0; 32])
            || self.source_context_digest == Digest32V0([0; 32])
            || self.target_context_digest == Digest32V0([0; 32])
            || self.rows_digest == Digest32V0([0; 32])
            || self.state_root == Digest32V0([0; 32])
            || self.snapshot_digest != self.canonical_digest()
            || self.row_count > MAX_EXPORT_ROWS_V0
            || self.generation > i64::MAX as u64
        {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::InvalidDurableSnapshot,
            ));
        }
        validate_target_rows_v0(&self.rows).map_err(DurableDeltaStoreErrorV0::Protocol)?;
        if self.row_count != self.rows.len() as u64
            || target_rows_digest_v0(&self.rows) != self.rows_digest
        {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::SnapshotRowsMismatch,
            ));
        }
        let recomputed = root_builder
            .recompute_target_root(self.target_schema_digest, self.rows.iter())
            .map_err(|error| DurableDeltaStoreErrorV0::RootBuilder(error.to_string()))?;
        if recomputed != self.state_root {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::SnapshotRootMismatch,
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum DurableDeltaStoreErrorV0 {
    Protocol(MigrationErrorV0),
    RootBuilder(String),
    Sqlite(String),
    Io(String),
}

impl fmt::Display for DurableDeltaStoreErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "durable delta protocol rejected input: {error}"),
            Self::RootBuilder(error) => {
                write!(f, "durable delta root recomputation failed: {error}")
            }
            Self::Sqlite(error) => write!(f, "durable delta sqlite failure: {error}"),
            Self::Io(error) => write!(f, "durable delta filesystem failure: {error}"),
        }
    }
}

impl Error for DurableDeltaStoreErrorV0 {}

/// A small, real SQLite staging/install adapter for incremental target state.
/// Each install uses one immediate transaction, verifies the target root and
/// row digest before commit, then reopens and reads metadata after commit. It
/// is intentionally a M07 integration primitive: no signer/finality authority,
/// network transport, pruning, or production availability claim is attached.
#[derive(Clone, Debug)]
pub struct SqliteIncrementalStateStoreV0 {
    path: PathBuf,
    plan_digest: Digest32V0,
    target_schema_digest: Digest32V0,
}

impl SqliteIncrementalStateStoreV0 {
    pub fn initialize<R>(
        path: impl Into<PathBuf>,
        plan_digest: Digest32V0,
        target_schema_digest: Digest32V0,
        source_context: SourceCheckpointContextV0,
        rows: &[TargetRowV0],
        root_builder: &R,
    ) -> Result<Self, DurableDeltaStoreErrorV0>
    where
        R: TargetRootBuilderV0,
        R::Error: fmt::Display,
    {
        if plan_digest == Digest32V0([0; 32]) || target_schema_digest == Digest32V0([0; 32]) {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::InvalidIncrementalDelta,
            ));
        }
        source_context
            .validate()
            .map_err(DurableDeltaStoreErrorV0::Protocol)?;
        validate_target_rows_v0(rows).map_err(DurableDeltaStoreErrorV0::Protocol)?;
        let state_root = root_builder
            .recompute_target_root(target_schema_digest, rows.iter())
            .map_err(|error| DurableDeltaStoreErrorV0::RootBuilder(error.to_string()))?;
        if state_root == Digest32V0([0; 32]) {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::InvalidTargetRoot,
            ));
        }
        let path = path.into();
        prepare_store_parent_v0(&path)?;
        let (temporary_path, temporary_file) = reserve_temporary_store_file_v0(&path)?;
        let mut published = false;
        let result = (|| {
            let mut connection = Connection::open_with_flags(
                &temporary_path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            connection
                .pragma_update(None, "application_id", DURABLE_STORE_APP_ID_V0)
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            connection
                .pragma_update(None, "user_version", 1_i64)
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            configure_durable_connection_v0(&connection)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            transaction
                .execute_batch(&format!("{DURABLE_META_SQL_V0};{DURABLE_ROWS_SQL_V0};"))
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            for row in rows {
                transaction
                    .execute(
                        "INSERT INTO migration_delta_rows_v0(namespace,key,value) VALUES(?1,?2,?3)",
                        params![&row.namespace, &row.key, &row.value],
                    )
                    .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            }
            transaction
                .execute(
                    "INSERT INTO migration_delta_meta_v0(singleton,plan_digest,schema_digest,source_context_digest,target_context_digest,rows_digest,state_root,row_count,generation,last_delta_digest) VALUES(1,?1,?2,?3,?3,?4,?5,?6,0,?7)",
                    params![
                        &plan_digest.0[..],
                        &target_schema_digest.0[..],
                        &source_context.canonical_digest().0[..],
                        &target_rows_digest_v0(rows).0[..],
                        &state_root.0[..],
                        rows.len() as i64,
                        &[0_u8; 32][..],
                    ],
                )
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            transaction
                .commit()
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            drop(connection);
            sync_store_file_v0(&temporary_file, &temporary_path)?;
            remove_temporary_store_sidecars_v0(&temporary_path)?;
            let temporary_store = Self {
                path: temporary_path.clone(),
                plan_digest,
                target_schema_digest,
            };
            let readback = temporary_store.readback_with_root_builder_v0(root_builder)?;
            if readback.state_root != state_root || readback.row_count != rows.len() as u64 {
                return Err(DurableDeltaStoreErrorV0::Protocol(
                    MigrationErrorV0::DurableReadbackMismatch,
                ));
            }
            fs::hard_link(&temporary_path, &path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    DurableDeltaStoreErrorV0::Protocol(MigrationErrorV0::StoreAlreadyInitialized)
                } else {
                    DurableDeltaStoreErrorV0::Io(error.to_string())
                }
            })?;
            published = true;
            fs::remove_file(&temporary_path)
                .map_err(|error| DurableDeltaStoreErrorV0::Io(error.to_string()))?;
            sync_store_parent_v0(&path)?;
            let store = Self {
                path,
                plan_digest,
                target_schema_digest,
            };
            let readback = store.readback_with_root_builder_v0(root_builder)?;
            if readback.state_root != state_root || readback.row_count != rows.len() as u64 {
                return Err(DurableDeltaStoreErrorV0::Protocol(
                    MigrationErrorV0::DurableReadbackMismatch,
                ));
            }
            Ok(store)
        })();
        if !published {
            remove_temporary_store_artifacts_v0(&temporary_path);
        }
        result
    }

    /// Open and validate the closed-world schema plus metadata. This method
    /// intentionally does not recompute the state root; use
    /// [`Self::open_existing_with_root_builder_v0`] at an integrity boundary.
    pub fn open_existing(
        path: impl Into<PathBuf>,
        plan_digest: Digest32V0,
        target_schema_digest: Digest32V0,
    ) -> Result<Self, DurableDeltaStoreErrorV0> {
        let path = path.into();
        validate_existing_store_path_v0(&path)?;
        let store = Self {
            path,
            plan_digest,
            target_schema_digest,
        };
        let _ = store.readback_v0()?;
        Ok(store)
    }

    pub fn open_existing_with_root_builder_v0<R>(
        path: impl Into<PathBuf>,
        plan_digest: Digest32V0,
        target_schema_digest: Digest32V0,
        root_builder: &R,
    ) -> Result<Self, DurableDeltaStoreErrorV0>
    where
        R: TargetRootBuilderV0,
        R::Error: fmt::Display,
    {
        let store = Self::open_existing(path, plan_digest, target_schema_digest)?;
        store.readback_with_root_builder_v0(root_builder)?;
        Ok(store)
    }

    pub fn read_rows_v0(&self) -> Result<Vec<TargetRowV0>, DurableDeltaStoreErrorV0> {
        let connection = self.open_connection()?;
        read_rows_from_connection_v0(&connection)
    }

    /// Read metadata and rows from one pinned SQLite snapshot.  Keeping these
    /// reads in one transaction prevents a committed delta from being joined
    /// with the predecessor metadata (or vice versa) during recovery/export.
    fn read_snapshot_v0(
        &self,
    ) -> Result<(DurableDeltaReadbackV0, Vec<TargetRowV0>), DurableDeltaStoreErrorV0> {
        let mut connection = self.open_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
        let metadata = transaction
            .query_row(
                "SELECT plan_digest,schema_digest,source_context_digest,target_context_digest,rows_digest,state_root,row_count,generation,last_delta_digest FROM migration_delta_meta_v0 WHERE singleton=1",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, i64>(6)?, row.get::<_, i64>(7)?, row.get::<_, Vec<u8>>(8)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?
            .ok_or(DurableDeltaStoreErrorV0::Protocol(MigrationErrorV0::StoreSchemaMismatch))?;
        let decode = |bytes: Vec<u8>| -> Result<Digest32V0, DurableDeltaStoreErrorV0> {
            <[u8; 32]>::try_from(bytes.as_slice())
                .map(Digest32V0)
                .map_err(|_| {
                    DurableDeltaStoreErrorV0::Protocol(MigrationErrorV0::StoreSchemaMismatch)
                })
        };
        let plan = decode(metadata.0)?;
        let schema = decode(metadata.1)?;
        let source_context_digest = decode(metadata.2)?;
        let target_context_digest = decode(metadata.3)?;
        if plan != self.plan_digest
            || schema != self.target_schema_digest
            || source_context_digest == Digest32V0([0; 32])
            || target_context_digest == Digest32V0([0; 32])
            || metadata.6 < 0
            || metadata.7 < 0
        {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::DurableStoreMismatch,
            ));
        }
        #[cfg(test)]
        test_pause_after_snapshot_metadata_v0();
        let rows = read_rows_from_connection_v0(&transaction)?;
        let rows_digest = target_rows_digest_v0(&rows);
        let readback = DurableDeltaReadbackV0 {
            plan_digest: plan,
            target_schema_digest: schema,
            rows_digest,
            state_root: decode(metadata.5)?,
            source_context_digest,
            target_context_digest,
            row_count: metadata.6 as u64,
            generation: metadata.7 as u64,
            last_delta_digest: decode(metadata.8)?,
        };
        if readback.row_count != rows.len() as u64 || readback.rows_digest != decode(metadata.4)? {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::DurableReadbackMismatch,
            ));
        }
        transaction
            .commit()
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
        Ok((readback, rows))
    }

    pub fn readback_v0(&self) -> Result<DurableDeltaReadbackV0, DurableDeltaStoreErrorV0> {
        self.read_snapshot_v0().map(|(readback, _)| readback)
    }

    fn read_snapshot_with_root_builder_v0<R>(
        &self,
        root_builder: &R,
    ) -> Result<(DurableDeltaReadbackV0, Vec<TargetRowV0>), DurableDeltaStoreErrorV0>
    where
        R: TargetRootBuilderV0,
        R::Error: fmt::Display,
    {
        let (readback, rows) = self.read_snapshot_v0()?;
        let recomputed = root_builder
            .recompute_target_root(self.target_schema_digest, rows.iter())
            .map_err(|error| DurableDeltaStoreErrorV0::RootBuilder(error.to_string()))?;
        if recomputed != readback.state_root {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::DurableReadbackMismatch,
            ));
        }
        Ok((readback, rows))
    }

    /// Read back metadata and independently recompute the root from the
    /// durable rows. Metadata-only readback remains available for cheap health
    /// checks; this method is the integrity gate used around installation.
    pub fn readback_with_root_builder_v0<R>(
        &self,
        root_builder: &R,
    ) -> Result<DurableDeltaReadbackV0, DurableDeltaStoreErrorV0>
    where
        R: TargetRootBuilderV0,
        R::Error: fmt::Display,
    {
        let (readback, _) = self.read_snapshot_with_root_builder_v0(root_builder)?;
        Ok(readback)
    }

    /// Export the exact durable rows and metadata at one integrity-checked
    /// generation.  This is a local staging handoff primitive: callers must
    /// authenticate any peer/transport and independently bind finality before
    /// treating the snapshot as a migration input.
    pub fn export_snapshot_v0<R>(
        &self,
        root_builder: &R,
    ) -> Result<DurableDeltaSnapshotV0, DurableDeltaStoreErrorV0>
    where
        R: TargetRootBuilderV0,
        R::Error: fmt::Display,
    {
        let (readback, rows) = self.read_snapshot_with_root_builder_v0(root_builder)?;
        let mut snapshot = DurableDeltaSnapshotV0 {
            plan_digest: readback.plan_digest,
            target_schema_digest: readback.target_schema_digest,
            source_context_digest: readback.source_context_digest,
            target_context_digest: readback.target_context_digest,
            rows_digest: readback.rows_digest,
            state_root: readback.state_root,
            row_count: readback.row_count,
            generation: readback.generation,
            last_delta_digest: readback.last_delta_digest,
            rows,
            snapshot_digest: Digest32V0([0; 32]),
        };
        snapshot.snapshot_digest = snapshot.canonical_digest();
        snapshot.validate(root_builder)?;
        Ok(snapshot)
    }

    /// Install a validated snapshot into a new closed-world SQLite store.
    /// Existing paths are rejected and no signer/finality state is imported.
    pub(crate) fn initialize_from_snapshot_v0<R>(
        path: impl Into<PathBuf>,
        snapshot: &DurableDeltaSnapshotV0,
        root_builder: &R,
    ) -> Result<Self, DurableDeltaStoreErrorV0>
    where
        R: TargetRootBuilderV0,
        R::Error: fmt::Display,
    {
        snapshot.validate(root_builder)?;
        let path = path.into();
        prepare_store_parent_v0(&path)?;
        // Build and verify the complete SQLite image under a unique temporary
        // inode in the same directory.  Publishing with hard_link only after
        // the readback succeeds means observers can see either no store or a
        // complete store; they can never observe a partially-created schema.
        let (temporary_path, temporary_file) = reserve_temporary_store_file_v0(&path)?;
        let mut published = false;
        let result = (|| {
            let mut connection = Connection::open_with_flags(
                &temporary_path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            connection
                .pragma_update(None, "application_id", DURABLE_STORE_APP_ID_V0)
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            connection
                .pragma_update(None, "user_version", 1_i64)
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            configure_durable_connection_v0(&connection)?;
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            transaction
                .execute_batch(&format!("{DURABLE_META_SQL_V0};{DURABLE_ROWS_SQL_V0};"))
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            for row in &snapshot.rows {
                transaction
                    .execute(
                        "INSERT INTO migration_delta_rows_v0(namespace,key,value) VALUES(?1,?2,?3)",
                        params![&row.namespace, &row.key, &row.value],
                    )
                    .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            }
            transaction
                .execute(
                    "INSERT INTO migration_delta_meta_v0(singleton,plan_digest,schema_digest,source_context_digest,target_context_digest,rows_digest,state_root,row_count,generation,last_delta_digest) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    params![
                        &snapshot.plan_digest.0[..],
                        &snapshot.target_schema_digest.0[..],
                        &snapshot.source_context_digest.0[..],
                        &snapshot.target_context_digest.0[..],
                        &snapshot.rows_digest.0[..],
                        &snapshot.state_root.0[..],
                        snapshot.row_count as i64,
                        snapshot.generation as i64,
                        &snapshot.last_delta_digest.0[..],
                    ],
                )
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            transaction
                .commit()
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;

            // WAL is required for the durable adapter, but the published image
            // must be self-contained.  Checkpoint it before closing and remove
            // only the temporary inode's sidecars below.
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            drop(connection);
            sync_store_file_v0(&temporary_file, &temporary_path)?;
            remove_temporary_store_sidecars_v0(&temporary_path)?;

            let temporary_store = Self {
                path: temporary_path.clone(),
                plan_digest: snapshot.plan_digest,
                target_schema_digest: snapshot.target_schema_digest,
            };
            let readback = temporary_store.readback_with_root_builder_v0(root_builder)?;
            if readback.plan_digest != snapshot.plan_digest
                || readback.target_schema_digest != snapshot.target_schema_digest
                || readback.source_context_digest != snapshot.source_context_digest
                || readback.target_context_digest != snapshot.target_context_digest
                || readback.rows_digest != snapshot.rows_digest
                || readback.state_root != snapshot.state_root
                || readback.row_count != snapshot.row_count
                || readback.generation != snapshot.generation
                || readback.last_delta_digest != snapshot.last_delta_digest
            {
                return Err(DurableDeltaStoreErrorV0::Protocol(
                    MigrationErrorV0::DurableReadbackMismatch,
                ));
            }

            // create_new above protects the temporary path.  hard_link gives a
            // no-overwrite publication primitive, so a concurrent initializer
            // wins cleanly with StoreAlreadyInitialized.
            fs::hard_link(&temporary_path, &path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    DurableDeltaStoreErrorV0::Protocol(MigrationErrorV0::StoreAlreadyInitialized)
                } else {
                    DurableDeltaStoreErrorV0::Io(error.to_string())
                }
            })?;
            published = true;
            fs::remove_file(&temporary_path)
                .map_err(|error| DurableDeltaStoreErrorV0::Io(error.to_string()))?;
            sync_store_parent_v0(&path)?;

            Ok(Self {
                path,
                plan_digest: snapshot.plan_digest,
                target_schema_digest: snapshot.target_schema_digest,
            })
        })();
        if !published {
            remove_temporary_store_artifacts_v0(&temporary_path);
        }
        result
    }

    /// Install a snapshot while binding both persisted context digests to
    /// caller-supplied finalized checkpoint identities. The internal
    /// [`Self::initialize_from_snapshot_v0`] helper remains available only
    /// for local staging; this public variant is the safe handoff boundary
    /// when a node has separately verified source/target checkpoint contexts.
    pub(crate) fn initialize_from_snapshot_bound_v0<R>(
        path: impl Into<PathBuf>,
        snapshot: &DurableDeltaSnapshotV0,
        source_context: SourceCheckpointContextV0,
        target_context: SourceCheckpointContextV0,
        root_builder: &R,
    ) -> Result<Self, DurableDeltaStoreErrorV0>
    where
        R: TargetRootBuilderV0,
        R::Error: fmt::Display,
    {
        snapshot.validate(root_builder)?;
        source_context
            .validate()
            .map_err(DurableDeltaStoreErrorV0::Protocol)?;
        target_context
            .validate()
            .map_err(DurableDeltaStoreErrorV0::Protocol)?;
        let same_context = source_context == target_context;
        let valid_progression = source_context.chain_id == target_context.chain_id
            && source_context.protocol_digest == target_context.protocol_digest
            && target_context.height > source_context.height
            && target_context.epoch >= source_context.epoch
            && target_context.epoch <= source_context.epoch.saturating_add(1);
        if snapshot.source_context_digest != source_context.canonical_digest()
            || snapshot.target_context_digest != target_context.canonical_digest()
            || target_context.state_root != snapshot.state_root
            || (!same_context && !valid_progression)
        {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::SourceCheckpointContextMismatch,
            ));
        }
        Self::initialize_from_snapshot_v0(path, snapshot, root_builder)
    }

    /// Install a snapshot using contexts that were issued by
    /// [`verify_source_checkpoint_context_v0`].  A node integration should
    /// use this entrypoint instead of passing raw peer context structs; the
    /// underlying no-clobber publication and persisted context CAS remain the
    /// same as the lower-level staging path.
    pub fn initialize_from_verified_snapshot_v0<R>(
        path: impl Into<PathBuf>,
        snapshot: &DurableDeltaSnapshotV0,
        source_context: &VerifiedSourceCheckpointContextV0,
        target_context: &VerifiedSourceCheckpointContextV0,
        root_builder: &R,
    ) -> Result<Self, DurableDeltaStoreErrorV0>
    where
        R: TargetRootBuilderV0,
        R::Error: fmt::Display,
    {
        Self::initialize_from_snapshot_bound_v0(
            path,
            snapshot,
            source_context.context,
            target_context.context,
            root_builder,
        )
    }

    pub fn apply_delta_v0<R>(
        &self,
        delta: &IncrementalStateDeltaV0,
        root_builder: &R,
    ) -> Result<DurableDeltaInstallReceiptV0, DurableDeltaStoreErrorV0>
    where
        R: TargetRootBuilderV0,
        R::Error: fmt::Display,
    {
        if delta.plan_digest != self.plan_digest
            || delta.target_schema_digest != self.target_schema_digest
        {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::PlanSchemaMismatch,
            ));
        }
        let (before, base_rows) = self.read_snapshot_v0()?;
        if before.state_root != delta.base_state_root
            || before.rows_digest != delta.base_rows_digest
            || before.row_count != delta.base_row_count
        {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::BaseStateMismatch,
            ));
        }
        if before.last_delta_digest != delta.delta_digest
            && before.target_context_digest != delta.source_context.canonical_digest()
        {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::SourceCheckpointContextMismatch,
            ));
        }
        let target_rows = apply_incremental_delta_v0(
            delta,
            &delta.source_context,
            &delta.target_context,
            &base_rows,
            root_builder,
        )
        .map_err(|error| match error {
            IncrementalDeltaErrorV0::Protocol(error) => DurableDeltaStoreErrorV0::Protocol(error),
            IncrementalDeltaErrorV0::RootBuilder(error) => {
                DurableDeltaStoreErrorV0::RootBuilder(error.to_string())
            }
        })?;

        // An empty delta has identical base and target state.  Its exact
        // replay therefore passes the base-state check above, unlike a
        // non-empty delta whose target becomes the next base.  Treat an
        // already committed digest as an idempotent durable operation so a
        // retry cannot manufacture additional generations.
        if before.last_delta_digest == delta.delta_digest {
            if before.rows_digest != delta.target_rows_digest
                || before.state_root != delta.target_state_root
                || before.row_count != delta.target_row_count
                || before.target_context_digest != delta.target_context.canonical_digest()
            {
                return Err(DurableDeltaStoreErrorV0::Protocol(
                    MigrationErrorV0::DurableReadbackMismatch,
                ));
            }
            return Ok(DurableDeltaInstallReceiptV0 {
                previous_root: before.state_root,
                installed_root: before.state_root,
                generation: before.generation,
                delta_digest: before.last_delta_digest,
            });
        }

        let mut connection = self.open_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
        for entry in &delta.entries {
            if entry.value.is_some() {
                transaction.execute(
                    "INSERT INTO migration_delta_rows_v0(namespace,key,value) VALUES(?1,?2,?3) ON CONFLICT(namespace,key) DO UPDATE SET value=excluded.value",
                    params![&entry.namespace, &entry.key, entry.value.as_ref().expect("checked")],
                ).map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            } else {
                transaction
                    .execute(
                        "DELETE FROM migration_delta_rows_v0 WHERE namespace=?1 AND key=?2",
                        params![&entry.namespace, &entry.key],
                    )
                    .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
            }
        }
        #[cfg(test)]
        test_pause_after_delta_rows_v0();
        let stored_rows_digest = target_rows_digest_v0(&target_rows);
        let changed = transaction
            .execute(
                "UPDATE migration_delta_meta_v0 SET target_context_digest=?1,rows_digest=?2,state_root=?3,row_count=?4,generation=generation+1,last_delta_digest=?5 WHERE singleton=1 AND generation=?6 AND rows_digest=?7 AND state_root=?8 AND target_context_digest=?9",
                params![
                    &delta.target_context.canonical_digest().0[..],
                    &stored_rows_digest.0[..],
                    &delta.target_state_root.0[..],
                    target_rows.len() as i64,
                    &delta.delta_digest.0[..],
                    before.generation as i64,
                    &before.rows_digest.0[..],
                    &before.state_root.0[..],
                    &before.target_context_digest.0[..],
                ],
            )
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
        if changed != 1 {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::BaseStateMismatch,
            ));
        }
        transaction
            .commit()
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
        let after = self.readback_with_root_builder_v0(root_builder)?;
        if after.state_root != delta.target_state_root
            || after.rows_digest != delta.target_rows_digest
            || after.row_count != delta.target_row_count
            || after.last_delta_digest != delta.delta_digest
            || after.target_context_digest != delta.target_context.canonical_digest()
            || after.generation != before.generation.saturating_add(1)
        {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::DurableReadbackMismatch,
            ));
        }
        Ok(DurableDeltaInstallReceiptV0 {
            previous_root: before.state_root,
            installed_root: after.state_root,
            generation: after.generation,
            delta_digest: after.last_delta_digest,
        })
    }

    fn open_connection(&self) -> Result<Connection, DurableDeltaStoreErrorV0> {
        validate_existing_store_path_v0(&self.path)?;
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
        verify_durable_connection_v0(&connection)?;
        let application_id = connection
            .pragma_query_value(None, "application_id", |row| row.get::<_, i64>(0))
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
        let user_version = connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
        if application_id != DURABLE_STORE_APP_ID_V0 || user_version != 1 {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::StoreSchemaMismatch,
            ));
        }
        let mut statement = connection
            .prepare(
                "SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
        let objects = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
        if objects
            != vec![
                ("migration_delta_meta_v0".to_owned(), "table".to_owned()),
                ("migration_delta_rows_v0".to_owned(), "table".to_owned()),
            ]
        {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::StoreSchemaMismatch,
            ));
        }
        drop(statement);
        Ok(connection)
    }
}

fn prepare_store_parent_v0(path: &Path) -> Result<(), DurableDeltaStoreErrorV0> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::StoreAlreadyInitialized,
            ));
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(DurableDeltaStoreErrorV0::Io(error.to_string()));
        }
        Err(_) => {}
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| DurableDeltaStoreErrorV0::Io(error.to_string()))?;
    }
    reject_store_path_ancestors_v0(path)?;
    reject_store_sidecars_v0(path)?;
    Ok(())
}

/// Reserve a temporary store inode in the destination directory.  The
/// temporary name is deliberately unrelated to the destination basename so
/// that a crash cannot leave an apparently valid final store.  `hard_link`
/// publishes this inode only after the complete image has been checked.
fn reserve_temporary_store_file_v0(
    destination: &Path,
) -> Result<(PathBuf, fs::File), DurableDeltaStoreErrorV0> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let process_id = std::process::id();
    for _ in 0..1024 {
        let nonce = TEMPORARY_STORE_NONCE_V0.fetch_add(1, Ordering::Relaxed);
        let temporary_path = parent.join(format!(
            ".trnm-migration-init-{process_id:08x}-{nonce:016x}"
        ));
        match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&temporary_path)
        {
            Ok(file) => {
                file.sync_all()
                    .map_err(|error| DurableDeltaStoreErrorV0::Io(error.to_string()))?;
                return Ok((temporary_path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(DurableDeltaStoreErrorV0::Io(error.to_string())),
        }
    }
    Err(DurableDeltaStoreErrorV0::Io(
        "could not reserve a unique temporary migration store path".to_owned(),
    ))
}

fn remove_temporary_store_sidecars_v0(path: &Path) -> Result<(), DurableDeltaStoreErrorV0> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::remove_file(PathBuf::from(sidecar)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(DurableDeltaStoreErrorV0::Io(error.to_string())),
        }
    }
    Ok(())
}

fn remove_temporary_store_artifacts_v0(path: &Path) {
    let _ = remove_temporary_store_sidecars_v0(path);
    let _ = fs::remove_file(path);
}

fn sync_store_parent_v0(path: &Path) -> Result<(), DurableDeltaStoreErrorV0> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::File::open(parent)
        .and_then(|parent| parent.sync_all())
        .map_err(|error| DurableDeltaStoreErrorV0::Io(error.to_string()))
}

fn sync_store_file_v0(file: &fs::File, path: &Path) -> Result<(), DurableDeltaStoreErrorV0> {
    file.sync_all()
        .map_err(|error| DurableDeltaStoreErrorV0::Io(error.to_string()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::File::open(parent)
        .and_then(|parent| parent.sync_all())
        .map_err(|error| DurableDeltaStoreErrorV0::Io(error.to_string()))
}

fn validate_existing_store_path_v0(path: &Path) -> Result<(), DurableDeltaStoreErrorV0> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| DurableDeltaStoreErrorV0::Io(error.to_string()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(DurableDeltaStoreErrorV0::Io(
            "incremental state store path is not a regular file".to_owned(),
        ));
    }
    reject_store_path_ancestors_v0(path)?;
    reject_store_sidecars_v0(path)
}

fn reject_store_sidecars_v0(path: &Path) -> Result<(), DurableDeltaStoreErrorV0> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        if let Ok(metadata) = fs::symlink_metadata(PathBuf::from(sidecar)) {
            // WAL/SHM files are normal for this adapter. A sidecar symlink is
            // different: SQLite could follow it to an operator-controlled
            // path, so it remains a closed-world path violation.
            if metadata.file_type().is_symlink() {
                return Err(DurableDeltaStoreErrorV0::Io(
                    "incremental state store sidecar is a symlink".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn reject_store_path_ancestors_v0(path: &Path) -> Result<(), DurableDeltaStoreErrorV0> {
    let mut current = Some(
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    );
    while let Some(parent) = current {
        match fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(DurableDeltaStoreErrorV0::Io(
                    "incremental state store parent path is a symlink".to_owned(),
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(DurableDeltaStoreErrorV0::Io(
                    "incremental state store parent path is not a directory".to_owned(),
                ));
            }
            Ok(_) => {}
            Err(error) => {
                return Err(DurableDeltaStoreErrorV0::Io(error.to_string()));
            }
        }
        current = parent
            .parent()
            .filter(|ancestor| !ancestor.as_os_str().is_empty());
    }
    Ok(())
}

fn read_rows_from_connection_v0(
    connection: &Connection,
) -> Result<Vec<TargetRowV0>, DurableDeltaStoreErrorV0> {
    let mut statement = connection
        .prepare("SELECT namespace,key,value FROM migration_delta_rows_v0 ORDER BY namespace,key")
        .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
    let mapped = statement
        .query_map([], |row| {
            Ok(TargetRowV0 {
                namespace: row.get(0)?,
                key: row.get(1)?,
                value: row.get(2)?,
            })
        })
        .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
    let rows = mapped
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
    validate_target_rows_v0(&rows).map_err(DurableDeltaStoreErrorV0::Protocol)?;
    Ok(rows)
}

/// All durable writes use WAL + FULL synchronous mode and an IMMEDIATE
/// transaction.  This makes a committed metadata/root update survive a
/// process restart while ensuring a killed writer rolls back its uncommitted
/// row mutations.  A different journal mode is a schema/operational mismatch,
/// not a best-effort downgrade.
fn configure_durable_connection_v0(
    connection: &Connection,
) -> Result<(), DurableDeltaStoreErrorV0> {
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
    if journal_mode.to_ascii_lowercase() != "wal" {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
    }
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
    let synchronous: i64 = connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
    if journal_mode.to_ascii_lowercase() != "wal" || synchronous != 2 {
        return Err(DurableDeltaStoreErrorV0::Protocol(
            MigrationErrorV0::StoreSchemaMismatch,
        ));
    }
    connection
        .busy_timeout(std::time::Duration::from_millis(250))
        .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
    Ok(())
}

fn verify_durable_connection_v0(connection: &Connection) -> Result<(), DurableDeltaStoreErrorV0> {
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
    let synchronous: i64 = connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
    if journal_mode.to_ascii_lowercase() != "wal" || synchronous != 2 {
        return Err(DurableDeltaStoreErrorV0::Protocol(
            MigrationErrorV0::StoreSchemaMismatch,
        ));
    }
    connection
        .busy_timeout(std::time::Duration::from_millis(250))
        .map_err(|error| DurableDeltaStoreErrorV0::Sqlite(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
fn test_pause_after_delta_rows_v0() {
    let Ok(marker) = std::env::var("TRNM_MIGRATION_SIGKILL_PAUSE_FILE") else {
        return;
    };
    let marker = PathBuf::from(marker);
    let _ = std::fs::write(&marker, b"rows-updated-before-commit\n");
    loop {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(test)]
static PAUSE_AFTER_SNAPSHOT_METADATA_V0: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static SNAPSHOT_METADATA_REACHED_V0: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
std::thread_local! {
    static SNAPSHOT_METADATA_PAUSE_ARMED_V0: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn test_pause_after_snapshot_metadata_v0() {
    let armed = SNAPSHOT_METADATA_PAUSE_ARMED_V0.with(std::cell::Cell::get);
    if !armed {
        return;
    }
    SNAPSHOT_METADATA_REACHED_V0.store(true, std::sync::atomic::Ordering::SeqCst);
    while PAUSE_AFTER_SNAPSHOT_METADATA_V0.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::yield_now();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationPlanV0 {
    pub source_chain_id: Digest32V0,
    pub source_protocol_digest: Digest32V0,
    pub source_schema_digest: Digest32V0,
    pub source_height: u64,
    pub source_export_header_digest: Digest32V0,
    pub target_chain_id: Digest32V0,
    pub target_protocol_digest: Digest32V0,
    pub target_schema_digest: Digest32V0,
    pub target_genesis_id: Digest32V0,
    pub no_fallback: bool,
    pub downgrade_prohibited: bool,
    pub plan_digest: Digest32V0,
}

impl MigrationPlanV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.migration.plan.v0",
            &[
                &self.source_chain_id.0,
                &self.source_protocol_digest.0,
                &self.source_schema_digest.0,
                &self.source_height.to_be_bytes(),
                &self.source_export_header_digest.0,
                &self.target_chain_id.0,
                &self.target_protocol_digest.0,
                &self.target_schema_digest.0,
                &self.target_genesis_id.0,
                &[u8::from(self.no_fallback)],
                &[u8::from(self.downgrade_prohibited)],
            ],
        )
    }

    pub fn validate(&self, export: &VerifiedExportV0) -> Result<(), MigrationErrorV0> {
        if !self.no_fallback
            || !self.downgrade_prohibited
            || self.source_chain_id == Digest32V0([0; 32])
            || self.source_protocol_digest == Digest32V0([0; 32])
            || self.source_schema_digest == Digest32V0([0; 32])
            || self.source_chain_id != export.header.source_chain_id
            || self.source_protocol_digest != export.header.source_protocol_digest
            || self.source_schema_digest != export.header.source_schema_digest
            || self.source_height != export.header.source_height
            || self.source_export_header_digest != export.header.header_digest
            || self.target_chain_id == Digest32V0([0; 32])
            || self.target_chain_id == self.source_chain_id
            || self.target_protocol_digest == Digest32V0([0; 32])
            || self.target_schema_digest == Digest32V0([0; 32])
            || self.target_genesis_id == Digest32V0([0; 32])
            || self.plan_digest == Digest32V0([0; 32])
            || self.plan_digest != self.canonical_digest()
        {
            return Err(MigrationErrorV0::InvalidMigrationPlan);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationProjectionV0 {
    pub plan_digest: Digest32V0,
    pub source_export_root: Digest32V0,
    pub source_ordered_rows_digest: Digest32V0,
    pub target_row_count: u64,
    pub target_rows_digest: Digest32V0,
    pub target_state_root: Digest32V0,
    pub target_genesis_id: Digest32V0,
    pub rows: Vec<TargetRowV0>,
}

impl MigrationProjectionV0 {
    /// Digest of the projection commitment carried across the host handoff.
    /// Rows are represented by their independently checked digest; the durable
    /// delta store remains the source of the complete installed rows.
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.migration.projection.v0",
            &[
                &self.plan_digest.0,
                &self.source_export_root.0,
                &self.source_ordered_rows_digest.0,
                &self.target_row_count.to_be_bytes(),
                &self.target_rows_digest.0,
                &self.target_state_root.0,
                &self.target_genesis_id.0,
            ],
        )
    }
}

pub fn project_and_recompute_v0<P, R>(
    plan: &MigrationPlanV0,
    export: &VerifiedExportV0,
    source_rows: &[ExportRowV0],
    projector: &P,
    root_builder: &R,
) -> Result<MigrationProjectionV0, MigrationProjectionErrorV0<P::Error, R::Error>>
where
    P: TargetProjectorV0,
    R: TargetRootBuilderV0,
{
    plan.validate(export)
        .map_err(MigrationProjectionErrorV0::Protocol)?;
    validate_verified_rows_v0(export, source_rows).map_err(MigrationProjectionErrorV0::Protocol)?;
    let mut rows = Vec::new();
    let mut unique = BTreeSet::new();
    for source in source_rows {
        if let Some(row) = projector
            .project(source)
            .map_err(MigrationProjectionErrorV0::Projector)?
        {
            row.validate()
                .map_err(MigrationProjectionErrorV0::Protocol)?;
            if !unique.insert((row.namespace.clone(), row.key.clone())) {
                return Err(MigrationProjectionErrorV0::Protocol(
                    MigrationErrorV0::DuplicateTargetKey,
                ));
            }
            rows.push(row);
        }
    }
    rows.sort();
    let mut digest_builder = Sha256::new();
    digest_builder.update(b"trnm.migration.target-rows.v0");
    for row in &rows {
        digest_builder
            .update(ExportRowV0::canonical_digest(&row.namespace, &row.key, &row.value).0);
    }
    let target_rows_digest = Digest32V0(digest_builder.finalize().into());
    let target_state_root = root_builder
        .recompute_target_root(plan.target_schema_digest, rows.iter())
        .map_err(MigrationProjectionErrorV0::RootBuilder)?;
    if target_state_root == Digest32V0([0; 32]) {
        return Err(MigrationProjectionErrorV0::Protocol(
            MigrationErrorV0::InvalidTargetRoot,
        ));
    }
    Ok(MigrationProjectionV0 {
        plan_digest: plan.plan_digest,
        source_export_root: export.header.export_root,
        source_ordered_rows_digest: export.ordered_rows_digest,
        target_row_count: rows.len() as u64,
        target_rows_digest,
        target_state_root,
        target_genesis_id: plan.target_genesis_id,
        rows,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CutoverAttestationV0 {
    pub signer_id: Digest32V0,
    pub plan_digest: Digest32V0,
    pub target_state_root: Digest32V0,
    pub target_genesis_id: Digest32V0,
    pub signature_digest: Digest32V0,
}

pub trait CutoverSignatureVerifierV0 {
    type Error: Error + Send + Sync + 'static;

    fn verify_attestation(&self, attestation: &CutoverAttestationV0) -> Result<u64, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CutoverAgreementV0 {
    pub plan_digest: Digest32V0,
    pub target_state_root: Digest32V0,
    pub target_genesis_id: Digest32V0,
    pub signed_weight: u64,
    pub required_weight: u64,
    pub signer_set_digest: Digest32V0,
    pub agreement_digest: Digest32V0,
}

impl CutoverAgreementV0 {
    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.migration.cutover-agreement-record.v0",
            &[
                &self.plan_digest.0,
                &self.target_state_root.0,
                &self.target_genesis_id.0,
                &self.signed_weight.to_be_bytes(),
                &self.required_weight.to_be_bytes(),
                &self.signer_set_digest.0,
            ],
        )
    }
}

pub fn verify_cutover_agreement_v0<V>(
    verifier: &V,
    projection: &MigrationProjectionV0,
    required_weight: u64,
    attestations: &[CutoverAttestationV0],
) -> Result<CutoverAgreementV0, MigrationHostErrorV0<V::Error>>
where
    V: CutoverSignatureVerifierV0,
{
    if required_weight == 0
        || projection.plan_digest == Digest32V0([0; 32])
        || projection.target_state_root == Digest32V0([0; 32])
        || projection.target_genesis_id == Digest32V0([0; 32])
        || attestations.is_empty()
        || attestations.len() > MAX_CUTOVER_SIGNERS_V0
    {
        return Err(MigrationHostErrorV0::Protocol(
            MigrationErrorV0::InvalidCutoverAgreement,
        ));
    }

    let mut canonical = attestations.to_vec();
    canonical.sort_by_key(|attestation| attestation.signer_id);
    let mut previous_signer = None;
    let mut weighted = Vec::with_capacity(canonical.len());
    let mut signed_weight = 0_u64;
    for attestation in canonical {
        if attestation.signer_id == Digest32V0([0; 32])
            || attestation.plan_digest != projection.plan_digest
            || attestation.target_state_root != projection.target_state_root
            || attestation.target_genesis_id != projection.target_genesis_id
            || attestation.signature_digest == Digest32V0([0; 32])
            || previous_signer == Some(attestation.signer_id)
        {
            return Err(MigrationHostErrorV0::Protocol(
                MigrationErrorV0::InvalidCutoverAgreement,
            ));
        }
        previous_signer = Some(attestation.signer_id);
        let weight = verifier
            .verify_attestation(&attestation)
            .map_err(MigrationHostErrorV0::CutoverSignature)?;
        if weight == 0 {
            return Err(MigrationHostErrorV0::Protocol(
                MigrationErrorV0::InvalidCutoverAgreement,
            ));
        }
        signed_weight = signed_weight
            .checked_add(weight)
            .ok_or(MigrationHostErrorV0::Protocol(
                MigrationErrorV0::WeightOverflow,
            ))?;
        weighted.push((attestation.signer_id, weight));
    }
    if signed_weight < required_weight {
        return Err(MigrationHostErrorV0::Protocol(
            MigrationErrorV0::InsufficientCutoverWeight,
        ));
    }
    let mut signer_hasher = Sha256::new();
    signer_hasher.update(b"trnm.migration.cutover-signers.v0");
    for (signer_id, weight) in weighted {
        signer_hasher.update(signer_id.0);
        signer_hasher.update(weight.to_be_bytes());
    }
    let signer_set_digest = Digest32V0(signer_hasher.finalize().into());
    let agreement_digest = Digest32V0::hash(
        b"trnm.migration.cutover-agreement.v0",
        &[
            &projection.plan_digest.0,
            &projection.target_state_root.0,
            &projection.target_genesis_id.0,
            &signed_weight.to_be_bytes(),
            &required_weight.to_be_bytes(),
            &signer_set_digest.0,
        ],
    );
    Ok(CutoverAgreementV0 {
        plan_digest: projection.plan_digest,
        target_state_root: projection.target_state_root,
        target_genesis_id: projection.target_genesis_id,
        signed_weight,
        required_weight,
        signer_set_digest,
        agreement_digest,
    })
}

/// Host-owned durable migration handoff state. A projection in memory never
/// implies that a state-sync store was installed or that runtime activation is
/// safe.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationHandoffStateV0 {
    VerifiedSource = 1,
    ProjectedDelta = 2,
    DurableInstall = 3,
    ReadbackCas = 4,
    CutoverAgreed = 5,
    RuntimeReady = 6,
    Fenced = 255,
}

impl TryFrom<u8> for MigrationHandoffStateV0 {
    type Error = MigrationHandoffErrorV0;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::VerifiedSource),
            2 => Ok(Self::ProjectedDelta),
            3 => Ok(Self::DurableInstall),
            4 => Ok(Self::ReadbackCas),
            5 => Ok(Self::CutoverAgreed),
            6 => Ok(Self::RuntimeReady),
            255 => Ok(Self::Fenced),
            _ => Err(MigrationHandoffErrorV0::Codec(
                "unknown handoff state".into(),
            )),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationReadinessModuleV0 {
    M01 = 1,
    M02 = 2,
    M08 = 8,
}

impl TryFrom<u8> for MigrationReadinessModuleV0 {
    type Error = MigrationHandoffErrorV0;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::M01),
            2 => Ok(Self::M02),
            8 => Ok(Self::M08),
            _ => Err(MigrationHandoffErrorV0::Codec(
                "unknown readiness module".into(),
            )),
        }
    }
}

/// Receipt supplied by the real M01/M02/M08 owner. This crate validates only
/// the typed module and nonzero digest; it never manufactures external proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationReadinessReceiptV0 {
    pub module: MigrationReadinessModuleV0,
    pub receipt_digest: Digest32V0,
}

impl MigrationReadinessReceiptV0 {
    pub fn validate(self) -> Result<(), MigrationHandoffErrorV0> {
        if self.receipt_digest == Digest32V0([0; 32]) {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidReadinessReceipt,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HandoffInstallV0 {
    previous_root: Digest32V0,
    installed_root: Digest32V0,
    generation: u64,
    delta_digest: Digest32V0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HandoffReadbackV0 {
    plan_digest: Digest32V0,
    target_schema_digest: Digest32V0,
    source_context_digest: Digest32V0,
    target_context_digest: Digest32V0,
    rows_digest: Digest32V0,
    state_root: Digest32V0,
    row_count: u64,
    generation: u64,
    last_delta_digest: Digest32V0,
}

/// One complete handoff record. Its digest covers all fields and every
/// optional field has an explicit presence marker in the durable encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationHandoffRecordV0 {
    pub state: MigrationHandoffStateV0,
    pub revision: u64,
    pub plan_digest: Digest32V0,
    pub target_schema_digest: Digest32V0,
    pub source_binding_digest: Digest32V0,
    pub source_context_digest: Digest32V0,
    pub source_state_root: Digest32V0,
    pub target_context_digest: Digest32V0,
    pub projection_digest: Digest32V0,
    pub target_rows_digest: Digest32V0,
    pub target_genesis_id: Digest32V0,
    pub target_state_root: Digest32V0,
    pub rollback_floor: u64,
    pub store_identity_digest: Option<Digest32V0>,
    install: Option<HandoffInstallV0>,
    readback: Option<HandoffReadbackV0>,
    cutover: Option<CutoverAgreementV0>,
    readiness: [Option<MigrationReadinessReceiptV0>; 3],
    pub fence_reason_digest: Option<Digest32V0>,
    pub record_digest: Digest32V0,
}

impl MigrationHandoffRecordV0 {
    pub fn new_verified_source(
        plan: &MigrationPlanV0,
        source_binding: &FinalizedSourceBindingV0,
        source_context: &VerifiedSourceCheckpointContextV0,
        rollback_floor: u64,
    ) -> Result<Self, MigrationHandoffErrorV0> {
        if plan.plan_digest == Digest32V0([0; 32])
            || plan.plan_digest != plan.canonical_digest()
            || plan.target_schema_digest == Digest32V0([0; 32])
            || rollback_floor == 0
            || rollback_floor > plan.source_height
            || source_binding.binding_digest() == Digest32V0([0; 32])
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidHandoffRecord,
            ));
        }
        let context = source_context.context();
        if context.chain_id != source_binding.source_chain_id()
            || context.protocol_digest != source_binding.source_protocol_digest()
            || context.height != source_binding.source_height()
            || context.state_root != source_binding.source_state_root()
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::SourceCheckpointContextMismatch,
            ));
        }
        let mut record = Self {
            state: MigrationHandoffStateV0::VerifiedSource,
            revision: 0,
            plan_digest: plan.plan_digest,
            target_schema_digest: plan.target_schema_digest,
            source_binding_digest: source_binding.binding_digest(),
            source_context_digest: context.canonical_digest(),
            source_state_root: context.state_root,
            target_context_digest: Digest32V0([0; 32]),
            projection_digest: Digest32V0([0; 32]),
            target_rows_digest: Digest32V0([0; 32]),
            target_genesis_id: plan.target_genesis_id,
            target_state_root: Digest32V0([0; 32]),
            rollback_floor,
            store_identity_digest: None,
            install: None,
            readback: None,
            cutover: None,
            readiness: [None, None, None],
            fence_reason_digest: None,
            record_digest: Digest32V0([0; 32]),
        };
        record.record_digest = record.canonical_digest();
        Ok(record)
    }

    #[must_use]
    pub fn canonical_digest(&self) -> Digest32V0 {
        Digest32V0::hash(
            b"trnm.migration.handoff-record.v0",
            &[&self.canonical_bytes()],
        )
    }
    #[must_use]
    pub fn projection_digest(&self) -> Digest32V0 {
        self.projection_digest
    }
    #[must_use]
    pub fn install_receipt(&self) -> Option<DurableDeltaInstallReceiptV0> {
        self.install.map(|v| DurableDeltaInstallReceiptV0 {
            previous_root: v.previous_root,
            installed_root: v.installed_root,
            generation: v.generation,
            delta_digest: v.delta_digest,
        })
    }
    #[must_use]
    pub fn readback(&self) -> Option<DurableDeltaReadbackV0> {
        self.readback.map(|v| DurableDeltaReadbackV0 {
            plan_digest: v.plan_digest,
            target_schema_digest: v.target_schema_digest,
            source_context_digest: v.source_context_digest,
            target_context_digest: v.target_context_digest,
            rows_digest: v.rows_digest,
            state_root: v.state_root,
            row_count: v.row_count,
            generation: v.generation,
            last_delta_digest: v.last_delta_digest,
        })
    }
    #[must_use]
    pub fn cutover_agreement(&self) -> Option<CutoverAgreementV0> {
        self.cutover
    }
    #[must_use]
    pub fn readiness(&self) -> &[Option<MigrationReadinessReceiptV0>; 3] {
        &self.readiness
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1024);
        b.extend_from_slice(b"MHOF");
        b.extend_from_slice(&1_u16.to_be_bytes());
        b.push(self.state as u8);
        put_u64(&mut b, self.revision);
        for d in [
            self.plan_digest,
            self.target_schema_digest,
            self.source_binding_digest,
            self.source_context_digest,
            self.source_state_root,
            self.target_context_digest,
            self.projection_digest,
            self.target_rows_digest,
            self.target_genesis_id,
            self.target_state_root,
        ] {
            put_digest(&mut b, d);
        }
        put_u64(&mut b, self.rollback_floor);
        put_optional_digest(&mut b, self.store_identity_digest);
        if let Some(v) = self.install {
            b.push(1);
            put_digest(&mut b, v.previous_root);
            put_digest(&mut b, v.installed_root);
            put_u64(&mut b, v.generation);
            put_digest(&mut b, v.delta_digest);
        } else {
            b.push(0);
        }
        if let Some(v) = self.readback {
            b.push(1);
            for d in [
                v.plan_digest,
                v.target_schema_digest,
                v.source_context_digest,
                v.target_context_digest,
                v.rows_digest,
                v.state_root,
            ] {
                put_digest(&mut b, d);
            }
            put_u64(&mut b, v.row_count);
            put_u64(&mut b, v.generation);
            put_digest(&mut b, v.last_delta_digest);
        } else {
            b.push(0);
        }
        if let Some(v) = self.cutover {
            b.push(1);
            for d in [v.plan_digest, v.target_state_root, v.target_genesis_id] {
                put_digest(&mut b, d);
            }
            put_u64(&mut b, v.signed_weight);
            put_u64(&mut b, v.required_weight);
            put_digest(&mut b, v.signer_set_digest);
            put_digest(&mut b, v.agreement_digest);
        } else {
            b.push(0);
        }
        for v in self.readiness {
            if let Some(v) = v {
                b.push(1);
                b.push(v.module as u8);
                put_digest(&mut b, v.receipt_digest);
            } else {
                b.push(0);
            }
        }
        put_optional_digest(&mut b, self.fence_reason_digest);
        b
    }
    fn encode(&self) -> Vec<u8> {
        let mut b = self.canonical_bytes();
        b.extend_from_slice(&self.record_digest.0);
        b
    }
    fn validate(&self) -> Result<(), MigrationHandoffErrorV0> {
        if self.record_digest == Digest32V0([0; 32])
            || self.record_digest != self.canonical_digest()
            || self.plan_digest == Digest32V0([0; 32])
            || self.target_schema_digest == Digest32V0([0; 32])
            || self.source_binding_digest == Digest32V0([0; 32])
            || self.source_context_digest == Digest32V0([0; 32])
            || self.source_state_root == Digest32V0([0; 32])
            || self.target_genesis_id == Digest32V0([0; 32])
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidHandoffRecord,
            ));
        }
        if self.state == MigrationHandoffStateV0::Fenced {
            if self.fence_reason_digest.is_none()
                || self.fence_reason_digest == Some(Digest32V0([0; 32]))
            {
                return Err(MigrationHandoffErrorV0::Protocol(
                    MigrationErrorV0::InvalidHandoffRecord,
                ));
            }
            return Ok(());
        }
        if self.fence_reason_digest.is_some() {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidHandoffRecord,
            ));
        }
        if self.state == MigrationHandoffStateV0::VerifiedSource
            && (self.projection_digest != Digest32V0([0; 32])
                || self.target_context_digest != Digest32V0([0; 32])
                || self.target_state_root != Digest32V0([0; 32])
                || self.target_rows_digest != Digest32V0([0; 32])
                || self.store_identity_digest.is_some()
                || self.install.is_some()
                || self.readback.is_some()
                || self.cutover.is_some())
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidHandoffRecord,
            ));
        }
        if self.state as u8 >= MigrationHandoffStateV0::ProjectedDelta as u8
            && (self.projection_digest == Digest32V0([0; 32])
                || self.target_context_digest == Digest32V0([0; 32])
                || self.target_state_root == Digest32V0([0; 32])
                || self.target_rows_digest == Digest32V0([0; 32]))
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidHandoffRecord,
            ));
        }
        if matches!(
            self.state,
            MigrationHandoffStateV0::DurableInstall
                | MigrationHandoffStateV0::ReadbackCas
                | MigrationHandoffStateV0::CutoverAgreed
                | MigrationHandoffStateV0::RuntimeReady
        ) && (self.store_identity_digest.is_none()
            || self.install.is_none()
            || self.readback.is_none())
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidHandoffRecord,
            ));
        }
        if matches!(
            self.state,
            MigrationHandoffStateV0::CutoverAgreed | MigrationHandoffStateV0::RuntimeReady
        ) && self.cutover.is_none()
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidHandoffRecord,
            ));
        }
        if self.state == MigrationHandoffStateV0::RuntimeReady
            && self.readiness.iter().any(Option::is_none)
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidReadinessReceipt,
            ));
        }
        for v in self.readiness.iter().flatten() {
            v.validate()?;
        }
        Ok(())
    }

    fn projected_delta(
        mut self,
        projection: &MigrationProjectionV0,
        source: &VerifiedSourceCheckpointContextV0,
        target: &VerifiedSourceCheckpointContextV0,
    ) -> Result<Self, MigrationHandoffErrorV0> {
        if self.state != MigrationHandoffStateV0::VerifiedSource
            || projection.plan_digest != self.plan_digest
            || projection.target_genesis_id != self.target_genesis_id
            || projection.target_state_root == Digest32V0([0; 32])
            || source.context_digest() != self.source_context_digest
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidHandoffTransition,
            ));
        }
        if projection.target_row_count != projection.rows.len() as u64
            || validate_target_rows_v0(&projection.rows).is_err()
            || target_rows_digest_v0(&projection.rows) != projection.target_rows_digest
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::VerifiedExportMismatch,
            ));
        }
        let s = source.context();
        let t = target.context();
        if t.chain_id != s.chain_id
            || t.protocol_digest != s.protocol_digest
            || t.height <= s.height
            || t.epoch < s.epoch
            || t.epoch > s.epoch.saturating_add(1)
            || t.state_root != projection.target_state_root
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::SourceCheckpointContextMismatch,
            ));
        }
        self.state = MigrationHandoffStateV0::ProjectedDelta;
        self.target_context_digest = t.canonical_digest();
        self.projection_digest = projection.canonical_digest();
        self.target_rows_digest = projection.target_rows_digest;
        self.target_state_root = projection.target_state_root;
        self.record_digest = self.canonical_digest();
        Ok(self)
    }
    fn durable_install(
        mut self,
        identity: Digest32V0,
        receipt: DurableDeltaInstallReceiptV0,
        readback: DurableDeltaReadbackV0,
    ) -> Result<Self, MigrationHandoffErrorV0> {
        if self.state != MigrationHandoffStateV0::ProjectedDelta
            || identity == Digest32V0([0; 32])
            || receipt.previous_root == Digest32V0([0; 32])
            || receipt.previous_root != self.source_state_root
            || receipt.installed_root != self.target_state_root
            || receipt.generation == 0
            || receipt.delta_digest == Digest32V0([0; 32])
            || readback.plan_digest != self.plan_digest
            || readback.target_schema_digest != self.target_schema_digest
            || readback.source_context_digest != self.source_context_digest
            || readback.target_context_digest != self.target_context_digest
            || readback.state_root != self.target_state_root
            || readback.rows_digest != self.target_rows_digest
            || readback.rows_digest == Digest32V0([0; 32])
            || readback.generation != receipt.generation
            || readback.last_delta_digest != receipt.delta_digest
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::DurableReadbackMismatch,
            ));
        }
        self.state = MigrationHandoffStateV0::DurableInstall;
        self.store_identity_digest = Some(identity);
        self.install = Some(HandoffInstallV0 {
            previous_root: receipt.previous_root,
            installed_root: receipt.installed_root,
            generation: receipt.generation,
            delta_digest: receipt.delta_digest,
        });
        self.readback = Some(HandoffReadbackV0 {
            plan_digest: readback.plan_digest,
            target_schema_digest: readback.target_schema_digest,
            source_context_digest: readback.source_context_digest,
            target_context_digest: readback.target_context_digest,
            rows_digest: readback.rows_digest,
            state_root: readback.state_root,
            row_count: readback.row_count,
            generation: readback.generation,
            last_delta_digest: readback.last_delta_digest,
        });
        self.record_digest = self.canonical_digest();
        Ok(self)
    }
    fn readback_cas(
        mut self,
        readback: DurableDeltaReadbackV0,
    ) -> Result<Self, MigrationHandoffErrorV0> {
        let expected = HandoffReadbackV0 {
            plan_digest: readback.plan_digest,
            target_schema_digest: readback.target_schema_digest,
            source_context_digest: readback.source_context_digest,
            target_context_digest: readback.target_context_digest,
            rows_digest: readback.rows_digest,
            state_root: readback.state_root,
            row_count: readback.row_count,
            generation: readback.generation,
            last_delta_digest: readback.last_delta_digest,
        };
        if self.state != MigrationHandoffStateV0::DurableInstall || self.readback != Some(expected)
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::DurableReadbackMismatch,
            ));
        }
        self.state = MigrationHandoffStateV0::ReadbackCas;
        self.record_digest = self.canonical_digest();
        Ok(self)
    }
    fn cutover_agreed(
        mut self,
        agreement: CutoverAgreementV0,
    ) -> Result<Self, MigrationHandoffErrorV0> {
        let expected = Digest32V0::hash(
            b"trnm.migration.cutover-agreement.v0",
            &[
                &agreement.plan_digest.0,
                &agreement.target_state_root.0,
                &agreement.target_genesis_id.0,
                &agreement.signed_weight.to_be_bytes(),
                &agreement.required_weight.to_be_bytes(),
                &agreement.signer_set_digest.0,
            ],
        );
        if self.state != MigrationHandoffStateV0::ReadbackCas
            || agreement.plan_digest != self.plan_digest
            || agreement.target_state_root != self.target_state_root
            || agreement.target_genesis_id != self.target_genesis_id
            || agreement.required_weight == 0
            || agreement.signed_weight < agreement.required_weight
            || agreement.agreement_digest == Digest32V0([0; 32])
            || agreement.agreement_digest != expected
        {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidCutoverAgreement,
            ));
        }
        self.state = MigrationHandoffStateV0::CutoverAgreed;
        self.cutover = Some(agreement);
        self.record_digest = self.canonical_digest();
        Ok(self)
    }
    fn runtime_ready(
        mut self,
        readiness: [MigrationReadinessReceiptV0; 3],
    ) -> Result<Self, MigrationHandoffErrorV0> {
        if self.state != MigrationHandoffStateV0::CutoverAgreed {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidHandoffTransition,
            ));
        }
        let expected = [
            MigrationReadinessModuleV0::M01,
            MigrationReadinessModuleV0::M02,
            MigrationReadinessModuleV0::M08,
        ];
        for (i, v) in readiness.into_iter().enumerate() {
            v.validate()?;
            if v.module != expected[i] {
                return Err(MigrationHandoffErrorV0::Protocol(
                    MigrationErrorV0::InvalidReadinessReceipt,
                ));
            }
            self.readiness[i] = Some(v);
        }
        self.state = MigrationHandoffStateV0::RuntimeReady;
        self.record_digest = self.canonical_digest();
        Ok(self)
    }
    fn fenced(mut self, reason: Digest32V0) -> Result<Self, MigrationHandoffErrorV0> {
        if reason == Digest32V0([0; 32]) {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidHandoffRecord,
            ));
        }
        self.state = MigrationHandoffStateV0::Fenced;
        self.fence_reason_digest = Some(reason);
        self.record_digest = self.canonical_digest();
        Ok(self)
    }
}

fn put_digest(b: &mut Vec<u8>, d: Digest32V0) {
    b.extend_from_slice(&d.0)
}
fn put_u64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_be_bytes())
}
fn put_optional_digest(b: &mut Vec<u8>, d: Option<Digest32V0>) {
    if let Some(d) = d {
        b.push(1);
        put_digest(b, d)
    } else {
        b.push(0)
    }
}

#[derive(Debug)]
pub enum MigrationHandoffErrorV0 {
    Protocol(MigrationErrorV0),
    Sqlite(String),
    Io(String),
    Codec(String),
    ConcurrentUpdate,
}
impl fmt::Display for MigrationHandoffErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "migration handoff rejected input: {e}"),
            Self::Sqlite(e) => write!(f, "migration handoff sqlite failure: {e}"),
            Self::Io(e) => write!(f, "migration handoff filesystem failure: {e}"),
            Self::Codec(e) => write!(f, "migration handoff codec failure: {e}"),
            Self::ConcurrentUpdate => f.write_str("migration handoff changed concurrently"),
        }
    }
}
impl Error for MigrationHandoffErrorV0 {}

const HANDOFF_STORE_APP_ID_V0: i64 = 0x484f_4630;
const HANDOFF_META_SQL_V0:&str="CREATE TABLE migration_handoff_record_v0 (singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL CHECK(revision>=0), record_digest BLOB NOT NULL CHECK(length(record_digest)=32), record BLOB NOT NULL CHECK(length(record)>0)) STRICT";

/// Durable handoff store. Each transition commits atomically, fsyncs the
/// database and parent, and decodes the committed record again before return.
#[derive(Clone, Debug)]
pub struct SqliteMigrationHandoffStoreV0 {
    path: PathBuf,
}

impl SqliteMigrationHandoffStoreV0 {
    pub fn initialize(
        path: impl Into<PathBuf>,
        record: MigrationHandoffRecordV0,
    ) -> Result<Self, MigrationHandoffErrorV0> {
        record.validate()?;
        let path = path.into();
        prepare_store_parent_handoff_v0(&path)?;
        let (tp, tf) = reserve_temporary_store_file_handoff_v0(&path)?;
        let mut published = false;
        let result = (|| {
            let mut c = open_handoff_connection_create_v0(&tp)?;
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
            tx.execute_batch(HANDOFF_META_SQL_V0)
                .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
            tx.execute("INSERT INTO migration_handoff_record_v0(singleton,revision,record_digest,record) VALUES(1,?1,?2,?3)",params![record.revision as i64,&record.record_digest.0[..],&record.encode()]).map_err(|e|MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
            tx.commit()
                .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
            c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
            drop(c);
            sync_store_file_v0(&tf, &tp).map_err(|e| MigrationHandoffErrorV0::Io(e.to_string()))?;
            remove_temporary_store_sidecars_v0(&tp)
                .map_err(|e| MigrationHandoffErrorV0::Io(e.to_string()))?;
            if (Self { path: tp.clone() }).readback_v0()?.record_digest != record.record_digest {
                return Err(MigrationHandoffErrorV0::Protocol(
                    MigrationErrorV0::DurableReadbackMismatch,
                ));
            }
            fs::hard_link(&tp, &path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    MigrationHandoffErrorV0::Protocol(MigrationErrorV0::StoreAlreadyInitialized)
                } else {
                    MigrationHandoffErrorV0::Io(e.to_string())
                }
            })?;
            published = true;
            fs::remove_file(&tp).map_err(|e| MigrationHandoffErrorV0::Io(e.to_string()))?;
            sync_store_parent_v0(&path).map_err(|e| MigrationHandoffErrorV0::Io(e.to_string()))?;
            let store = Self { path };
            if store.readback_v0()?.record_digest != record.record_digest {
                return Err(MigrationHandoffErrorV0::Protocol(
                    MigrationErrorV0::DurableReadbackMismatch,
                ));
            }
            Ok(store)
        })();
        if !published {
            remove_temporary_store_artifacts_v0(&tp)
        }
        result
    }
    pub fn open_existing(path: impl Into<PathBuf>) -> Result<Self, MigrationHandoffErrorV0> {
        let path = path.into();
        validate_existing_store_path_v0(&path)
            .map_err(|e| MigrationHandoffErrorV0::Io(e.to_string()))?;
        let s = Self { path };
        s.readback_v0()?;
        Ok(s)
    }
    pub fn readback_v0(&self) -> Result<MigrationHandoffRecordV0, MigrationHandoffErrorV0> {
        let c = self.open_connection()?;
        let (rev,digest,bytes)=c.query_row("SELECT revision,record_digest,record FROM migration_handoff_record_v0 WHERE singleton=1",[],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?))).optional().map_err(|e|MigrationHandoffErrorV0::Sqlite(e.to_string()))?.ok_or(MigrationHandoffErrorV0::Protocol(MigrationErrorV0::StoreSchemaMismatch))?;
        if rev < 0 {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::StoreSchemaMismatch,
            ));
        }
        let r = decode_handoff_record_v0(&bytes)?;
        let d = <[u8; 32]>::try_from(digest.as_slice())
            .map(Digest32V0)
            .map_err(|_| MigrationHandoffErrorV0::Codec("invalid digest length".into()))?;
        if r.revision != rev as u64 || r.record_digest != d {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::DurableReadbackMismatch,
            ));
        }
        Ok(r)
    }
    pub fn projected_delta_v0(
        &self,
        p: &MigrationProjectionV0,
        s: &VerifiedSourceCheckpointContextV0,
        t: &VerifiedSourceCheckpointContextV0,
    ) -> Result<MigrationHandoffRecordV0, MigrationHandoffErrorV0> {
        self.transition(|r| r.projected_delta(p, s, t))
    }
    pub fn durable_install_v0(
        &self,
        i: Digest32V0,
        receipt: DurableDeltaInstallReceiptV0,
        readback: DurableDeltaReadbackV0,
    ) -> Result<MigrationHandoffRecordV0, MigrationHandoffErrorV0> {
        self.transition(|r| r.durable_install(i, receipt, readback))
    }
    pub fn readback_cas_v0(
        &self,
        r: DurableDeltaReadbackV0,
    ) -> Result<MigrationHandoffRecordV0, MigrationHandoffErrorV0> {
        self.transition(|v| v.readback_cas(r))
    }
    pub fn cutover_agreed_v0(
        &self,
        a: CutoverAgreementV0,
    ) -> Result<MigrationHandoffRecordV0, MigrationHandoffErrorV0> {
        self.transition(|r| r.cutover_agreed(a))
    }
    pub fn runtime_ready_v0(
        &self,
        r: [MigrationReadinessReceiptV0; 3],
    ) -> Result<MigrationHandoffRecordV0, MigrationHandoffErrorV0> {
        self.transition(|v| v.runtime_ready(r))
    }
    pub fn fence_v0(
        &self,
        d: Digest32V0,
    ) -> Result<MigrationHandoffRecordV0, MigrationHandoffErrorV0> {
        self.transition(|v| v.fenced(d))
    }
    fn transition<F>(&self, apply: F) -> Result<MigrationHandoffRecordV0, MigrationHandoffErrorV0>
    where
        F: FnOnce(
            MigrationHandoffRecordV0,
        ) -> Result<MigrationHandoffRecordV0, MigrationHandoffErrorV0>,
    {
        let mut c = self.open_connection()?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
        let(rev,digest,bytes)=tx.query_row("SELECT revision,record_digest,record FROM migration_handoff_record_v0 WHERE singleton=1",[],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?))).map_err(|e|MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
        if rev < 0 {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::StoreSchemaMismatch,
            ));
        }
        let cur = decode_handoff_record_v0(&bytes)?;
        let sd = <[u8; 32]>::try_from(digest.as_slice())
            .map(Digest32V0)
            .map_err(|_| MigrationHandoffErrorV0::Codec("invalid digest length".into()))?;
        if cur.revision != rev as u64 || cur.record_digest != sd {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::DurableReadbackMismatch,
            ));
        }
        let mut next = apply(cur)?;
        next.revision = rev as u64 + 1;
        next.record_digest = next.canonical_digest();
        next.validate()?;
        let changed=tx.execute("UPDATE migration_handoff_record_v0 SET revision=?1,record_digest=?2,record=?3 WHERE singleton=1 AND revision=?4 AND record_digest=?5",params![next.revision as i64,&next.record_digest.0[..],&next.encode(),rev,&sd.0[..]]).map_err(|e|MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
        if changed != 1 {
            return Err(MigrationHandoffErrorV0::ConcurrentUpdate);
        }
        tx.commit()
            .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
        drop(c);
        sync_store_file_path_v0(&self.path)?;
        let rb = self.readback_v0()?;
        if rb != next {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::DurableReadbackMismatch,
            ));
        }
        Ok(rb)
    }
    fn open_connection(&self) -> Result<Connection, MigrationHandoffErrorV0> {
        validate_existing_store_path_v0(&self.path)
            .map_err(|e| MigrationHandoffErrorV0::Io(e.to_string()))?;
        let c = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
        verify_handoff_connection_v0(&c)?;
        let mut st = c
            .prepare(
                "SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
        let objects = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
        if objects != vec![("migration_handoff_record_v0".to_owned(), "table".to_owned())] {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::StoreSchemaMismatch,
            ));
        }
        drop(st);
        Ok(c)
    }
}

fn decode_handoff_record_v0(
    bytes: &[u8],
) -> Result<MigrationHandoffRecordV0, MigrationHandoffErrorV0> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], MigrationHandoffErrorV0> {
        let end = p
            .checked_add(n)
            .ok_or_else(|| MigrationHandoffErrorV0::Codec("length overflow".into()))?;
        let out = bytes
            .get(*p..end)
            .ok_or_else(|| MigrationHandoffErrorV0::Codec("truncated record".into()))?;
        *p = end;
        Ok(out)
    };
    let u64v = |p: &mut usize| -> Result<u64, MigrationHandoffErrorV0> {
        Ok(u64::from_be_bytes(take(p, 8)?.try_into().expect("fixed")))
    };
    let dig = |p: &mut usize| -> Result<Digest32V0, MigrationHandoffErrorV0> {
        Ok(Digest32V0(take(p, 32)?.try_into().expect("fixed")))
    };
    let optdig = |p: &mut usize| -> Result<Option<Digest32V0>, MigrationHandoffErrorV0> {
        match take(p, 1)?[0] {
            0 => Ok(None),
            1 => Ok(Some(dig(p)?)),
            _ => Err(MigrationHandoffErrorV0::Codec(
                "invalid optional flag".into(),
            )),
        }
    };
    if take(&mut p, 4)? != b"MHOF" || take(&mut p, 2)? != 1u16.to_be_bytes() {
        return Err(MigrationHandoffErrorV0::Codec(
            "invalid record header".into(),
        ));
    }
    let state = MigrationHandoffStateV0::try_from(take(&mut p, 1)?[0])?;
    let revision = u64v(&mut p)?;
    let plan_digest = dig(&mut p)?;
    let target_schema_digest = dig(&mut p)?;
    let source_binding_digest = dig(&mut p)?;
    let source_context_digest = dig(&mut p)?;
    let source_state_root = dig(&mut p)?;
    let target_context_digest = dig(&mut p)?;
    let projection_digest = dig(&mut p)?;
    let target_rows_digest = dig(&mut p)?;
    let target_genesis_id = dig(&mut p)?;
    let target_state_root = dig(&mut p)?;
    let rollback_floor = u64v(&mut p)?;
    let store_identity_digest = optdig(&mut p)?;
    let install = match take(&mut p, 1)?[0] {
        0 => None,
        1 => Some(HandoffInstallV0 {
            previous_root: dig(&mut p)?,
            installed_root: dig(&mut p)?,
            generation: u64v(&mut p)?,
            delta_digest: dig(&mut p)?,
        }),
        _ => {
            return Err(MigrationHandoffErrorV0::Codec(
                "invalid install flag".into(),
            ))
        }
    };
    let readback = match take(&mut p, 1)?[0] {
        0 => None,
        1 => Some(HandoffReadbackV0 {
            plan_digest: dig(&mut p)?,
            target_schema_digest: dig(&mut p)?,
            source_context_digest: dig(&mut p)?,
            target_context_digest: dig(&mut p)?,
            rows_digest: dig(&mut p)?,
            state_root: dig(&mut p)?,
            row_count: u64v(&mut p)?,
            generation: u64v(&mut p)?,
            last_delta_digest: dig(&mut p)?,
        }),
        _ => {
            return Err(MigrationHandoffErrorV0::Codec(
                "invalid readback flag".into(),
            ))
        }
    };
    let cutover = match take(&mut p, 1)?[0] {
        0 => None,
        1 => Some(CutoverAgreementV0 {
            plan_digest: dig(&mut p)?,
            target_state_root: dig(&mut p)?,
            target_genesis_id: dig(&mut p)?,
            signed_weight: u64v(&mut p)?,
            required_weight: u64v(&mut p)?,
            signer_set_digest: dig(&mut p)?,
            agreement_digest: dig(&mut p)?,
        }),
        _ => {
            return Err(MigrationHandoffErrorV0::Codec(
                "invalid cutover flag".into(),
            ))
        }
    };
    let mut readiness = [None, None, None];
    for slot in &mut readiness {
        *slot = match take(&mut p, 1)?[0] {
            0 => None,
            1 => Some(MigrationReadinessReceiptV0 {
                module: MigrationReadinessModuleV0::try_from(take(&mut p, 1)?[0])?,
                receipt_digest: dig(&mut p)?,
            }),
            _ => {
                return Err(MigrationHandoffErrorV0::Codec(
                    "invalid readiness flag".into(),
                ))
            }
        };
    }
    let fence_reason_digest = optdig(&mut p)?;
    let record_digest = dig(&mut p)?;
    if p != bytes.len() {
        return Err(MigrationHandoffErrorV0::Codec(
            "trailing record bytes".into(),
        ));
    }
    let record = MigrationHandoffRecordV0 {
        state,
        revision,
        plan_digest,
        target_schema_digest,
        source_binding_digest,
        source_context_digest,
        source_state_root,
        target_context_digest,
        projection_digest,
        target_rows_digest,
        target_genesis_id,
        target_state_root,
        rollback_floor,
        store_identity_digest,
        install,
        readback,
        cutover,
        readiness,
        fence_reason_digest,
        record_digest,
    };
    record.validate()?;
    Ok(record)
}
fn open_handoff_connection_create_v0(path: &Path) -> Result<Connection, MigrationHandoffErrorV0> {
    let c = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
    c.pragma_update(None, "application_id", HANDOFF_STORE_APP_ID_V0)
        .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
    c.pragma_update(None, "user_version", 1_i64)
        .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
    configure_handoff_connection_v0(&c)?;
    Ok(c)
}
fn configure_handoff_connection_v0(c: &Connection) -> Result<(), MigrationHandoffErrorV0> {
    let mode: String = c
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
    if mode.to_ascii_lowercase() != "wal" {
        c.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
    }
    let mode: String = c
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
    let sync: i64 = c
        .pragma_query_value(None, "synchronous", |r| r.get(0))
        .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
    if mode.to_ascii_lowercase() != "wal" || sync != 2 {
        return Err(MigrationHandoffErrorV0::Protocol(
            MigrationErrorV0::StoreSchemaMismatch,
        ));
    }
    c.busy_timeout(std::time::Duration::from_millis(250))
        .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
    Ok(())
}
fn verify_handoff_connection_v0(c: &Connection) -> Result<(), MigrationHandoffErrorV0> {
    let id: i64 = c
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
    let ver: i64 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| MigrationHandoffErrorV0::Sqlite(e.to_string()))?;
    if id != HANDOFF_STORE_APP_ID_V0 || ver != 1 {
        return Err(MigrationHandoffErrorV0::Protocol(
            MigrationErrorV0::StoreSchemaMismatch,
        ));
    }
    configure_handoff_connection_v0(c)
}
fn prepare_store_parent_handoff_v0(path: &Path) -> Result<(), MigrationHandoffErrorV0> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::StoreAlreadyInitialized,
            ))
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(MigrationHandoffErrorV0::Io(e.to_string()))
        }
        Err(_) => {}
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| MigrationHandoffErrorV0::Io(e.to_string()))?;
    }
    reject_store_path_ancestors_v0(path).map_err(|e| MigrationHandoffErrorV0::Io(e.to_string()))?;
    reject_store_sidecars_v0(path).map_err(|e| MigrationHandoffErrorV0::Io(e.to_string()))?;
    Ok(())
}
fn reserve_temporary_store_file_handoff_v0(
    path: &Path,
) -> Result<(PathBuf, fs::File), MigrationHandoffErrorV0> {
    reserve_temporary_store_file_v0(path).map_err(|e| MigrationHandoffErrorV0::Io(e.to_string()))
}
fn sync_store_file_path_v0(path: &Path) -> Result<(), MigrationHandoffErrorV0> {
    let f = fs::File::open(path).map_err(|e| MigrationHandoffErrorV0::Io(e.to_string()))?;
    sync_store_file_v0(&f, path).map_err(|e| MigrationHandoffErrorV0::Io(e.to_string()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationErrorV0 {
    InvalidExportRow,
    ForbiddenAuthorityState,
    InvalidExportHeader,
    InvalidSourceBinding,
    RowsNotStrictlyOrdered,
    ExportRootMismatch,
    VerifiedExportMismatch,
    InvalidTargetRow,
    InvalidMigrationPlan,
    DuplicateTargetKey,
    InvalidTargetRoot,
    InvalidCutoverAgreement,
    InsufficientCutoverWeight,
    WeightOverflow,
    InvalidDeltaRow,
    InvalidIncrementalDelta,
    InvalidSourceCheckpointContext,
    SourceCheckpointContextMismatch,
    DeltaRootMismatch,
    DeltaRowsOutOfBounds,
    TargetRowsOutOfBounds,
    BaseStateMismatch,
    TargetStateMismatch,
    PlanSchemaMismatch,
    StoreAlreadyInitialized,
    StoreSchemaMismatch,
    DurableStoreMismatch,
    DurableReadbackMismatch,
    InvalidDurableSnapshot,
    SnapshotRowsMismatch,
    SnapshotRootMismatch,
    InvalidHandoffRecord,
    InvalidHandoffTransition,
    InvalidReadinessReceipt,
}

impl fmt::Display for MigrationErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidExportRow => "invalid source export row",
            Self::ForbiddenAuthorityState => "validator or node authority state cannot be migrated",
            Self::InvalidExportHeader => "invalid finalized export header",
            Self::InvalidSourceBinding => "finalized source binding is malformed or substituted",
            Self::RowsNotStrictlyOrdered => {
                "source export rows are not strictly ordered and unique"
            }
            Self::ExportRootMismatch => "source export root mismatch",
            Self::VerifiedExportMismatch => {
                "projection rows do not match the independently verified export"
            }
            Self::InvalidTargetRow => "invalid projected target row",
            Self::InvalidMigrationPlan => "migration plan is misbound or permits fallback",
            Self::DuplicateTargetKey => "projection produced a duplicate target key",
            Self::InvalidTargetRoot => "target root builder returned an invalid root",
            Self::InvalidCutoverAgreement => "cutover attestation is malformed or misbound",
            Self::InsufficientCutoverWeight => "cutover attestations do not meet required weight",
            Self::WeightOverflow => "cutover signer weight overflow",
            Self::InvalidDeltaRow => "invalid incremental delta row",
            Self::InvalidIncrementalDelta => "invalid incremental migration delta",
            Self::InvalidSourceCheckpointContext => {
                "incremental delta source checkpoint context is malformed"
            }
            Self::SourceCheckpointContextMismatch => {
                "incremental delta source checkpoint context does not match the verified target"
            }
            Self::DeltaRootMismatch => "incremental delta root mismatch",
            Self::DeltaRowsOutOfBounds => "incremental delta exceeds its row bound",
            Self::TargetRowsOutOfBounds => "target state exceeds its row bound",
            Self::BaseStateMismatch => "incremental delta base state mismatch",
            Self::TargetStateMismatch => "incremental delta target state mismatch",
            Self::PlanSchemaMismatch => "incremental delta plan or schema mismatch",
            Self::StoreAlreadyInitialized => "durable delta store already exists",
            Self::StoreSchemaMismatch => "durable delta store schema mismatch",
            Self::DurableStoreMismatch => "durable delta store metadata mismatch",
            Self::DurableReadbackMismatch => "durable delta readback mismatch",
            Self::InvalidDurableSnapshot => "durable delta snapshot is malformed",
            Self::SnapshotRowsMismatch => "durable delta snapshot rows mismatch",
            Self::SnapshotRootMismatch => "durable delta snapshot root mismatch",
            Self::InvalidHandoffRecord => "migration handoff record is malformed",
            Self::InvalidHandoffTransition => "migration handoff transition is out of order",
            Self::InvalidReadinessReceipt => "migration module readiness receipt is malformed",
        })
    }
}

impl Error for MigrationErrorV0 {}

#[derive(Debug)]
pub enum MigrationHostErrorV0<AdapterError> {
    Protocol(MigrationErrorV0),
    SourceFinality(AdapterError),
    SourceCheckpointContext(AdapterError),
    CutoverSignature(AdapterError),
}

impl<A: fmt::Display> fmt::Display for MigrationHostErrorV0<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "migration protocol rejected input: {error}"),
            Self::SourceFinality(error) => {
                write!(f, "source finality verification failed: {error}")
            }
            Self::SourceCheckpointContext(error) => {
                write!(f, "source checkpoint context verification failed: {error}")
            }
            Self::CutoverSignature(error) => {
                write!(f, "cutover signature verification failed: {error}")
            }
        }
    }
}

impl<A> Error for MigrationHostErrorV0<A> where A: Error + 'static {}

#[derive(Debug)]
pub enum MigrationProjectionErrorV0<ProjectorError, RootError> {
    Protocol(MigrationErrorV0),
    Projector(ProjectorError),
    RootBuilder(RootError),
}

impl<P: fmt::Display, R: fmt::Display> fmt::Display for MigrationProjectionErrorV0<P, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "migration projection rejected input: {error}"),
            Self::Projector(error) => write!(f, "target projection failed: {error}"),
            Self::RootBuilder(error) => write!(f, "target root recomputation failed: {error}"),
        }
    }
}

impl<P, R> Error for MigrationProjectionErrorV0<P, R>
where
    P: Error + 'static,
    R: Error + 'static,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn d(byte: u8) -> Digest32V0 {
        Digest32V0([byte; 32])
    }

    struct AcceptFinality;
    impl SourceFinalityVerifierV0 for AcceptFinality {
        type Error = Infallible;
        fn verify_finalized_export(
            &self,
            _header: &FinalizedExportHeaderV0,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl SourceCheckpointContextVerifierV0 for AcceptFinality {
        type Error = Infallible;

        fn verify_checkpoint_context(
            &self,
            _context: &SourceCheckpointContextV0,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct IdentityProjector;
    impl TargetProjectorV0 for IdentityProjector {
        type Error = Infallible;
        fn project(&self, source: &ExportRowV0) -> Result<Option<TargetRowV0>, Self::Error> {
            Ok(Some(TargetRowV0 {
                namespace: source.namespace.clone(),
                key: source.key.clone(),
                value: source.value.clone(),
            }))
        }
    }

    struct HashRoot;
    impl TargetRootBuilderV0 for HashRoot {
        type Error = Infallible;
        fn recompute_target_root<'a, I>(
            &self,
            target_schema_digest: Digest32V0,
            rows: I,
        ) -> Result<Digest32V0, Self::Error>
        where
            I: IntoIterator<Item = &'a TargetRowV0>,
        {
            let mut h = Sha256::new();
            h.update(b"test.target-root");
            h.update(target_schema_digest.0);
            for row in rows {
                h.update(ExportRowV0::canonical_digest(&row.namespace, &row.key, &row.value).0);
            }
            Ok(Digest32V0(h.finalize().into()))
        }
    }

    struct WeightOne;
    impl CutoverSignatureVerifierV0 for WeightOne {
        type Error = Infallible;
        fn verify_attestation(
            &self,
            _attestation: &CutoverAttestationV0,
        ) -> Result<u64, Self::Error> {
            Ok(1)
        }
    }

    fn row(byte: u8) -> ExportRowV0 {
        let namespace = b"accounts".to_vec();
        let key = vec![byte];
        let value = vec![byte, byte];
        ExportRowV0 {
            row_digest: ExportRowV0::canonical_digest(&namespace, &key, &value),
            namespace,
            key,
            value,
        }
    }

    fn target_row(byte: u8, value: u8) -> TargetRowV0 {
        TargetRowV0 {
            namespace: b"accounts".to_vec(),
            key: vec![byte],
            value: vec![value],
        }
    }

    fn source_context(
        rows: &[TargetRowV0],
        schema_digest: Digest32V0,
        block_byte: u8,
        height: u64,
        epoch: u64,
    ) -> SourceCheckpointContextV0 {
        let state_root = HashRoot
            .recompute_target_root(schema_digest, rows.iter())
            .unwrap();
        SourceCheckpointContextV0 {
            chain_id: d(70),
            protocol_digest: d(71),
            checkpoint_digest: d(block_byte.wrapping_add(1)),
            block_id: d(block_byte),
            height,
            epoch,
            state_root,
            validator_set_digest: d(72u8.wrapping_add(epoch as u8)),
            finality_proof_digest: d(block_byte.wrapping_add(2)),
        }
    }

    #[test]
    fn incremental_delta_recomputes_and_applies_exact_state() {
        let base = vec![target_row(1, 10), target_row(2, 20), target_row(4, 40)];
        let target = vec![target_row(2, 21), target_row(3, 30), target_row(4, 40)];
        let source = source_context(&base, d(91), 10, 1, 1);
        let target_context = source_context(&target, d(91), 11, 2, 2);
        let delta = derive_incremental_delta_v0(
            d(90),
            d(91),
            source,
            target_context,
            &base,
            &target,
            &HashRoot,
        )
        .unwrap();
        assert_eq!(
            delta.entries.len(),
            3,
            "delete, insert and update are distinct operations"
        );
        assert_eq!(delta.base_row_count, 3);
        assert_eq!(delta.target_row_count, 3);
        assert_eq!(
            apply_incremental_delta_v0(&delta, &source, &target_context, &base, &HashRoot).unwrap(),
            target
        );
    }

    struct RejectContext;
    impl SourceCheckpointContextVerifierV0 for RejectContext {
        type Error = std::io::Error;

        fn verify_checkpoint_context(
            &self,
            _context: &SourceCheckpointContextV0,
        ) -> Result<(), Self::Error> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "test finality rejection",
            ))
        }
    }

    #[test]
    fn verified_context_capability_is_required_for_typed_delta_path() {
        let base = vec![target_row(1, 10), target_row(2, 20)];
        let target = vec![target_row(1, 11), target_row(2, 20)];
        let source_raw = source_context(&base, d(121), 30, 4, 4);
        let target_raw = source_context(&target, d(121), 31, 5, 5);

        assert!(matches!(
            verify_source_checkpoint_context_v0(&RejectContext, source_raw),
            Err(MigrationHostErrorV0::SourceCheckpointContext(_))
        ));

        let source = verify_source_checkpoint_context_v0(&AcceptFinality, source_raw).unwrap();
        let target_cap = verify_source_checkpoint_context_v0(&AcceptFinality, target_raw).unwrap();
        assert_eq!(source.context_digest(), source_raw.canonical_digest());
        assert_ne!(source.verification_digest(), Digest32V0([0; 32]));

        let delta = derive_incremental_delta_verified_v0(
            d(120),
            d(121),
            &source,
            &target_cap,
            &base,
            &target,
            &HashRoot,
        )
        .unwrap();
        assert_eq!(
            apply_incremental_delta_verified_v0(&delta, &source, &target_cap, &base, &HashRoot,)
                .unwrap(),
            target
        );

        let foreign_target_raw = source_context(&target, d(121), 32, 6, 5);
        let foreign_target =
            verify_source_checkpoint_context_v0(&AcceptFinality, foreign_target_raw).unwrap();
        assert!(matches!(
            apply_incremental_delta_verified_v0(&delta, &source, &foreign_target, &base, &HashRoot,),
            Err(IncrementalDeltaErrorV0::Protocol(
                MigrationErrorV0::SourceCheckpointContextMismatch
            ))
        ));
    }

    #[test]
    fn incremental_delta_rejects_base_substitution_and_entry_tampering() {
        let base = vec![target_row(1, 10), target_row(2, 20)];
        let target = vec![target_row(1, 11), target_row(2, 20)];
        let source = source_context(&base, d(93), 20, 2, 2);
        let target_context = source_context(&target, d(93), 21, 3, 3);
        let delta = derive_incremental_delta_v0(
            d(92),
            d(93),
            source,
            target_context,
            &base,
            &target,
            &HashRoot,
        )
        .unwrap();
        let mut substituted = base.clone();
        substituted[0].value[0] = 99;
        assert!(matches!(
            apply_incremental_delta_v0(&delta, &source, &target_context, &substituted, &HashRoot,),
            Err(IncrementalDeltaErrorV0::Protocol(
                MigrationErrorV0::BaseStateMismatch
            ))
        ));

        let mut tampered = delta.clone();
        tampered.entries[0].value = Some(vec![77]);
        assert!(matches!(
            apply_incremental_delta_v0(&tampered, &source, &target_context, &base, &HashRoot),
            Err(IncrementalDeltaErrorV0::Protocol(
                MigrationErrorV0::InvalidDeltaRow
            ))
        ));
    }

    #[test]
    fn sqlite_incremental_store_commits_and_reopens_exact_readback() {
        let path = std::env::temp_dir().join(format!(
            "trnm-migration-delta-{}-{}.sqlite",
            std::process::id(),
            d(94).0[0]
        ));
        let _ = std::fs::remove_file(&path);
        let base = vec![target_row(1, 10), target_row(2, 20)];
        let target = vec![target_row(1, 11), target_row(3, 30)];
        let source = source_context(&base, d(96), 30, 4, 4);
        let target_context = source_context(&target, d(96), 31, 5, 4);
        let store = SqliteIncrementalStateStoreV0::initialize(
            &path,
            d(95),
            d(96),
            source,
            &base,
            &HashRoot,
        )
        .unwrap();
        let delta = derive_incremental_delta_v0(
            d(95),
            d(96),
            source,
            target_context,
            &base,
            &target,
            &HashRoot,
        )
        .unwrap();
        let receipt = store.apply_delta_v0(&delta, &HashRoot).unwrap();
        assert_eq!(receipt.previous_root, delta.base_state_root);
        assert_eq!(receipt.installed_root, delta.target_state_root);
        assert_eq!(receipt.generation, 1);
        let reopened = SqliteIncrementalStateStoreV0::open_existing_with_root_builder_v0(
            &path,
            d(95),
            d(96),
            &HashRoot,
        )
        .unwrap();
        assert_eq!(reopened.read_rows_v0().unwrap(), target);
        assert_eq!(
            reopened.readback_v0().unwrap().last_delta_digest,
            delta.delta_digest
        );
        assert_eq!(
            reopened
                .readback_with_root_builder_v0(&HashRoot)
                .unwrap()
                .state_root,
            delta.target_state_root
        );
        let tamper = Connection::open(&path).unwrap();
        tamper
            .execute(
                "UPDATE migration_delta_rows_v0 SET value=?1 WHERE namespace=?2 AND key=?3",
                params![&[99_u8][..], b"accounts".as_slice(), &[1_u8][..]],
            )
            .unwrap();
        assert!(matches!(
            reopened.readback_with_root_builder_v0(&HashRoot),
            Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::DurableReadbackMismatch
            ))
        ));
        assert!(matches!(
            SqliteIncrementalStateStoreV0::open_existing(&path, d(97), d(96)),
            Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::DurableStoreMismatch
            ))
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sqlite_incremental_store_rejects_same_root_foreign_checkpoint_context() {
        let path = std::env::temp_dir().join(format!(
            "trnm-migration-context-fence-{}-{}.sqlite",
            std::process::id(),
            d(106).0[0]
        ));
        let _ = std::fs::remove_file(&path);
        let base = vec![target_row(1, 10), target_row(2, 20)];
        let target = vec![target_row(1, 11), target_row(3, 30)];
        let source = source_context(&base, d(96), 30, 4, 4);
        let target_context = source_context(&target, d(96), 31, 5, 4);
        let foreign_source = source_context(&base, d(96), 32, 4, 4);
        let store = SqliteIncrementalStateStoreV0::initialize(
            &path,
            d(95),
            d(96),
            source,
            &base,
            &HashRoot,
        )
        .unwrap();
        // The foreign source has the exact same rows and recomputed root. Its
        // only difference is the finalized checkpoint identity. A rows/root
        // check alone would accept this delta; the persisted context digest
        // must reject it before any SQLite row mutation or generation bump.
        let foreign_delta = derive_incremental_delta_v0(
            d(95),
            d(96),
            foreign_source,
            target_context,
            &base,
            &target,
            &HashRoot,
        )
        .unwrap();
        assert!(matches!(
            store.apply_delta_v0(&foreign_delta, &HashRoot),
            Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::SourceCheckpointContextMismatch
            ))
        ));
        let readback = store.readback_with_root_builder_v0(&HashRoot).unwrap();
        assert_eq!(readback.generation, 0);
        assert_eq!(readback.state_root, source.state_root);
        assert_eq!(store.read_rows_v0().unwrap(), base);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sqlite_incremental_store_replays_empty_delta_idempotently() {
        let path = std::env::temp_dir().join(format!(
            "trnm-migration-empty-delta-{}-{}.sqlite",
            std::process::id(),
            d(103).0[0]
        ));
        let _ = std::fs::remove_file(&path);
        let rows = vec![target_row(1, 10), target_row(2, 20)];
        let source = source_context(&rows, d(96), 40, 5, 5);
        let target_context = source_context(&rows, d(96), 41, 6, 5);
        let store = SqliteIncrementalStateStoreV0::initialize(
            &path,
            d(95),
            d(96),
            source,
            &rows,
            &HashRoot,
        )
        .unwrap();
        let delta = derive_incremental_delta_v0(
            d(95),
            d(96),
            source,
            target_context,
            &rows,
            &rows,
            &HashRoot,
        )
        .unwrap();
        assert!(delta.entries.is_empty());
        let first = store.apply_delta_v0(&delta, &HashRoot).unwrap();
        assert_eq!(first.generation, 1);
        let replay = store.apply_delta_v0(&delta, &HashRoot).unwrap();
        assert_eq!(replay.generation, first.generation);
        assert_eq!(replay.delta_digest, delta.delta_digest);
        assert_eq!(store.readback_v0().unwrap().generation, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sqlite_incremental_readback_pins_metadata_and_rows_to_one_snapshot() {
        let path = std::env::temp_dir().join(format!(
            "trnm-migration-read-snapshot-{}-{}.sqlite",
            std::process::id(),
            d(104).0[0]
        ));
        let _ = std::fs::remove_file(&path);
        let base = vec![target_row(1, 10), target_row(2, 20)];
        let target = vec![target_row(1, 11), target_row(3, 30)];
        let source = source_context(&base, d(96), 50, 6, 6);
        let target_context = source_context(&target, d(96), 51, 7, 6);
        let store = SqliteIncrementalStateStoreV0::initialize(
            &path,
            d(95),
            d(96),
            source,
            &base,
            &HashRoot,
        )
        .unwrap();
        let delta = derive_incremental_delta_v0(
            d(95),
            d(96),
            source,
            target_context,
            &base,
            &target,
            &HashRoot,
        )
        .unwrap();

        PAUSE_AFTER_SNAPSHOT_METADATA_V0.store(true, std::sync::atomic::Ordering::SeqCst);
        SNAPSHOT_METADATA_REACHED_V0.store(false, std::sync::atomic::Ordering::SeqCst);
        let reader_store = store.clone();
        let reader = std::thread::spawn(move || {
            SNAPSHOT_METADATA_PAUSE_ARMED_V0.with(|armed| armed.set(true));
            reader_store.readback_with_root_builder_v0(&HashRoot)
        });
        for _ in 0..10_000 {
            if SNAPSHOT_METADATA_REACHED_V0.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            std::thread::yield_now();
        }
        assert!(SNAPSHOT_METADATA_REACHED_V0.load(std::sync::atomic::Ordering::SeqCst));

        // WAL permits the writer to commit after the reader's metadata query;
        // a pinned deferred transaction must still return the predecessor
        // metadata and predecessor rows as one coherent readback.
        store.apply_delta_v0(&delta, &HashRoot).unwrap();
        PAUSE_AFTER_SNAPSHOT_METADATA_V0.store(false, std::sync::atomic::Ordering::SeqCst);
        let before = reader.join().unwrap().unwrap();
        assert_eq!(before.generation, 0);
        assert_eq!(before.rows_digest, target_rows_digest_v0(&base));
        assert_eq!(store.readback_v0().unwrap().generation, 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sqlite_snapshot_export_import_is_exact_and_rejects_row_substitution() {
        let source_path = std::env::temp_dir().join(format!(
            "trnm-migration-snapshot-source-{}-{}.sqlite",
            std::process::id(),
            d(98).0[0]
        ));
        let target_path = std::env::temp_dir().join(format!(
            "trnm-migration-snapshot-target-{}-{}.sqlite",
            std::process::id(),
            d(99).0[0]
        ));
        let _ = std::fs::remove_file(&source_path);
        let _ = std::fs::remove_file(&target_path);
        let base = vec![target_row(1, 10), target_row(2, 20)];
        let target = vec![target_row(1, 11), target_row(3, 30)];
        let source_ctx = source_context(&base, d(96), 60, 7, 7);
        let target_ctx = source_context(&target, d(96), 61, 8, 7);
        let source = SqliteIncrementalStateStoreV0::initialize(
            &source_path,
            d(95),
            d(96),
            source_ctx,
            &base,
            &HashRoot,
        )
        .unwrap();
        let delta = derive_incremental_delta_v0(
            d(95),
            d(96),
            source_ctx,
            target_ctx,
            &base,
            &target,
            &HashRoot,
        )
        .unwrap();
        source.apply_delta_v0(&delta, &HashRoot).unwrap();
        let snapshot = source.export_snapshot_v0(&HashRoot).unwrap();
        let imported = SqliteIncrementalStateStoreV0::initialize_from_snapshot_bound_v0(
            &target_path,
            &snapshot,
            source_ctx,
            target_ctx,
            &HashRoot,
        )
        .unwrap();
        assert_eq!(imported.read_rows_v0().unwrap(), target);
        assert_eq!(imported.export_snapshot_v0(&HashRoot).unwrap(), snapshot);

        // Recomputing a snapshot digest does not authenticate a replacement
        // checkpoint context. The typed bound API requires the independently
        // verified contexts and rejects that substitution before publication.
        let foreign_source = source_context(&base, d(96), 62, 7, 7);
        let mut context_substituted = snapshot.clone();
        context_substituted.source_context_digest = foreign_source.canonical_digest();
        context_substituted.snapshot_digest = context_substituted.canonical_digest();
        assert!(matches!(
            SqliteIncrementalStateStoreV0::initialize_from_snapshot_bound_v0(
                std::env::temp_dir().join(format!(
                    "trnm-migration-snapshot-context-invalid-{}-{}.sqlite",
                    std::process::id(),
                    d(107).0[0]
                )),
                &context_substituted,
                source_ctx,
                target_ctx,
                &HashRoot,
            ),
            Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::SourceCheckpointContextMismatch
            ))
        ));
        assert!(matches!(
            SqliteIncrementalStateStoreV0::initialize_from_snapshot_v0(
                &target_path,
                &snapshot,
                &HashRoot,
            ),
            Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::StoreAlreadyInitialized
            ))
        ));

        let mut substituted = snapshot.clone();
        substituted.rows[0].value[0] = 99;
        assert!(matches!(
            SqliteIncrementalStateStoreV0::initialize_from_snapshot_v0(
                std::env::temp_dir().join(format!(
                    "trnm-migration-snapshot-invalid-{}-{}.sqlite",
                    std::process::id(),
                    d(100).0[0]
                )),
                &substituted,
                &HashRoot,
            ),
            Err(DurableDeltaStoreErrorV0::Protocol(
                MigrationErrorV0::SnapshotRowsMismatch
            ))
        ));
        let _ = std::fs::remove_file(source_path);
        let _ = std::fs::remove_file(target_path);
        let _ = std::fs::remove_file(std::env::temp_dir().join(format!(
            "trnm-migration-snapshot-invalid-{}-{}.sqlite",
            std::process::id(),
            d(100).0[0]
        )));
    }

    /// This is an actual process-level interruption: the child is killed while
    /// an IMMEDIATE SQLite transaction has changed rows but before metadata or
    /// commit.  Reopening the same file must expose the exact pre-transaction
    /// root.  It does not stand in for physical power-loss evidence.
    #[cfg(unix)]
    #[test]
    fn sqlite_process_kill_rolls_back_uncommitted_delta() {
        if std::env::var_os("TRNM_MIGRATION_SIGKILL_CHILD").is_some() {
            let path = std::env::var_os("TRNM_MIGRATION_SIGKILL_STORE").unwrap();
            let base = vec![target_row(1, 10), target_row(2, 20)];
            let target = vec![target_row(1, 11), target_row(3, 30)];
            let store = SqliteIncrementalStateStoreV0::open_existing(&path, d(95), d(96)).unwrap();
            let delta = derive_incremental_delta_v0(
                d(95),
                d(96),
                source_context(&base, d(96), 70, 8, 8),
                source_context(&target, d(96), 71, 9, 8),
                &base,
                &target,
                &HashRoot,
            )
            .unwrap();
            let _ = store.apply_delta_v0(&delta, &HashRoot);
            return;
        }
        let path = std::env::temp_dir().join(format!(
            "trnm-migration-sigkill-{}-{}.sqlite",
            std::process::id(),
            d(101).0[0]
        ));
        let marker = std::env::temp_dir().join(format!(
            "trnm-migration-sigkill-{}-{}.marker",
            std::process::id(),
            d(102).0[0]
        ));
        remove_sqlite_artifacts_v0(&path);
        let _ = std::fs::remove_file(&marker);
        let base = vec![target_row(1, 10), target_row(2, 20)];
        let source_ctx = source_context(&base, d(96), 70, 8, 8);
        let store = SqliteIncrementalStateStoreV0::initialize(
            &path,
            d(95),
            d(96),
            source_ctx,
            &base,
            &HashRoot,
        )
        .unwrap();
        let child_test = "tests::sqlite_process_kill_rolls_back_uncommitted_delta";
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(child_test)
            .arg("--nocapture")
            .env("TRNM_MIGRATION_SIGKILL_CHILD", "1")
            .env("TRNM_MIGRATION_SIGKILL_STORE", &path)
            .env("TRNM_MIGRATION_SIGKILL_PAUSE_FILE", &marker)
            .spawn()
            .unwrap();
        for _ in 0..250 {
            if marker.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(marker.exists(), "child never reached pre-commit failpoint");
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(
            !status.success(),
            "child unexpectedly exited before SIGKILL"
        );
        let reopened = SqliteIncrementalStateStoreV0::open_existing_with_root_builder_v0(
            &path,
            d(95),
            d(96),
            &HashRoot,
        )
        .unwrap();
        assert_eq!(reopened.read_rows_v0().unwrap(), base);
        assert_eq!(reopened.readback_v0().unwrap().generation, 0);
        assert_eq!(
            reopened
                .readback_with_root_builder_v0(&HashRoot)
                .unwrap()
                .state_root,
            store.readback_v0().unwrap().state_root
        );
        remove_sqlite_artifacts_v0(&path);
        let _ = std::fs::remove_file(marker);
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_incremental_store_rejects_symlinked_store_and_sidecar_paths() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "trnm-migration-path-{}-{}",
            std::process::id(),
            d(105).0[0]
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let real = root.join("real.sqlite");
        let empty_context = source_context(&[], d(96), 80, 9, 9);
        let store = SqliteIncrementalStateStoreV0::initialize(
            &real,
            d(95),
            d(96),
            empty_context,
            &[],
            &HashRoot,
        )
        .unwrap();

        let alias = root.join("alias.sqlite");
        symlink(&real, &alias).unwrap();
        assert!(matches!(
            SqliteIncrementalStateStoreV0::open_existing(&alias, d(95), d(96)),
            Err(DurableDeltaStoreErrorV0::Io(_))
        ));

        let sidecar = PathBuf::from(format!("{}-wal", real.display()));
        symlink(&real, &sidecar).unwrap();
        assert!(matches!(
            store.readback_v0(),
            Err(DurableDeltaStoreErrorV0::Io(_))
        ));

        let real_parent = root.join("real-parent");
        let alias_parent = root.join("alias-parent");
        std::fs::create_dir_all(&real_parent).unwrap();
        let nested = real_parent.join("nested.sqlite");
        let nested_store = SqliteIncrementalStateStoreV0::initialize(
            &nested,
            d(95),
            d(96),
            empty_context,
            &[],
            &HashRoot,
        )
        .unwrap();
        symlink(&real_parent, &alias_parent).unwrap();
        let nested_alias = alias_parent.join("nested.sqlite");
        assert!(matches!(
            SqliteIncrementalStateStoreV0::open_existing(&nested_alias, d(95), d(96)),
            Err(DurableDeltaStoreErrorV0::Io(_))
        ));
        drop(nested_store);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    fn remove_sqlite_artifacts_v0(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn finalized_export_projection_and_cutover_are_exactly_bound() {
        let rows = vec![row(1), row(2)];
        let export_root =
            merkle_root_v0(&rows.iter().map(|row| row.row_digest).collect::<Vec<_>>());
        let mut header = FinalizedExportHeaderV0 {
            source_chain_id: d(1),
            source_protocol_digest: d(2),
            source_height: 100,
            source_state_root: d(3),
            source_schema_digest: d(4),
            source_finality_proof_digest: d(5),
            row_count: rows.len() as u64,
            export_root,
            header_digest: d(0),
        };
        header.header_digest = header.canonical_digest();
        let export = verify_export_v0(&AcceptFinality, header, &rows).unwrap();
        let mut plan = MigrationPlanV0 {
            source_chain_id: header.source_chain_id,
            source_protocol_digest: header.source_protocol_digest,
            source_schema_digest: header.source_schema_digest,
            source_height: header.source_height,
            source_export_header_digest: header.header_digest,
            target_chain_id: d(6),
            target_protocol_digest: d(7),
            target_schema_digest: d(8),
            target_genesis_id: d(9),
            no_fallback: true,
            downgrade_prohibited: true,
            plan_digest: d(0),
        };
        plan.plan_digest = plan.canonical_digest();
        let projection =
            project_and_recompute_v0(&plan, &export, &rows, &IdentityProjector, &HashRoot).unwrap();
        let attestations = vec![
            CutoverAttestationV0 {
                signer_id: d(10),
                plan_digest: plan.plan_digest,
                target_state_root: projection.target_state_root,
                target_genesis_id: plan.target_genesis_id,
                signature_digest: d(11),
            },
            CutoverAttestationV0 {
                signer_id: d(12),
                plan_digest: plan.plan_digest,
                target_state_root: projection.target_state_root,
                target_genesis_id: plan.target_genesis_id,
                signature_digest: d(13),
            },
        ];
        let agreement =
            verify_cutover_agreement_v0(&WeightOne, &projection, 2, &attestations).unwrap();
        assert_eq!(agreement.signed_weight, 2);
    }

    #[test]
    fn signing_state_is_never_importable() {
        let namespace = b"signer_journal".to_vec();
        let key = vec![1];
        let value = vec![2];
        let row = ExportRowV0 {
            row_digest: ExportRowV0::canonical_digest(&namespace, &key, &value),
            namespace,
            key,
            value,
        };
        assert_eq!(
            row.validate().unwrap_err(),
            MigrationErrorV0::ForbiddenAuthorityState
        );
    }

    fn verified_fixture() -> (Vec<ExportRowV0>, VerifiedExportV0, MigrationPlanV0) {
        let rows = vec![row(1), row(2)];
        let export_root =
            merkle_root_v0(&rows.iter().map(|row| row.row_digest).collect::<Vec<_>>());
        let mut header = FinalizedExportHeaderV0 {
            source_chain_id: d(1),
            source_protocol_digest: d(2),
            source_height: 100,
            source_state_root: d(3),
            source_schema_digest: d(4),
            source_finality_proof_digest: d(5),
            row_count: rows.len() as u64,
            export_root,
            header_digest: d(0),
        };
        header.header_digest = header.canonical_digest();
        let export = verify_export_v0(&AcceptFinality, header, &rows).unwrap();
        let mut plan = MigrationPlanV0 {
            source_chain_id: header.source_chain_id,
            source_protocol_digest: header.source_protocol_digest,
            source_schema_digest: header.source_schema_digest,
            source_height: header.source_height,
            source_export_header_digest: header.header_digest,
            target_chain_id: d(6),
            target_protocol_digest: d(7),
            target_schema_digest: d(8),
            target_genesis_id: d(9),
            no_fallback: true,
            downgrade_prohibited: true,
            plan_digest: d(0),
        };
        plan.plan_digest = plan.canonical_digest();
        (rows, export, plan)
    }

    #[test]
    fn projection_rejects_rows_substituted_after_export_verification() {
        let (rows, export, plan) = verified_fixture();
        let mut substituted = rows.clone();
        substituted[1].value.push(99);
        substituted[1].row_digest = ExportRowV0::canonical_digest(
            &substituted[1].namespace,
            &substituted[1].key,
            &substituted[1].value,
        );
        assert!(matches!(
            project_and_recompute_v0(&plan, &export, &substituted, &IdentityProjector, &HashRoot),
            Err(MigrationProjectionErrorV0::Protocol(
                MigrationErrorV0::VerifiedExportMismatch
            ))
        ));
    }

    #[test]
    fn finalized_source_binding_rejects_context_and_row_set_substitution() {
        let (_rows, export, _plan) = verified_fixture();
        let binding = export.source_binding_v0();
        assert_eq!(binding.binding_digest, binding.canonical_digest());
        assert!(binding.validate_against(&export).is_ok());

        let mut wrong_context = binding;
        wrong_context.source_height += 1;
        wrong_context.binding_digest = wrong_context.canonical_digest();
        assert_eq!(
            wrong_context.validate_against(&export).unwrap_err(),
            MigrationErrorV0::InvalidSourceBinding
        );

        let mut wrong_export = export;
        wrong_export.ordered_rows_digest = d(99);
        assert_eq!(
            binding.validate_against(&wrong_export).unwrap_err(),
            MigrationErrorV0::InvalidSourceBinding
        );

        let mut wrong_digest = binding;
        wrong_digest.binding_digest = d(98);
        assert_eq!(
            wrong_digest.validate_against(&export).unwrap_err(),
            MigrationErrorV0::InvalidSourceBinding
        );
    }

    #[test]
    fn authority_namespace_prefixes_are_never_importable() {
        assert!(forbidden_authority_namespace(b"signer_journal/v2"));
        assert!(forbidden_authority_namespace(b"node_commit_ledger_archive"));
        assert!(!forbidden_authority_namespace(b"accounts"));
    }

    #[test]
    fn cutover_signer_commitment_is_permutation_invariant() {
        let (rows, export, plan) = verified_fixture();
        let projection =
            project_and_recompute_v0(&plan, &export, &rows, &IdentityProjector, &HashRoot).unwrap();
        let first = CutoverAttestationV0 {
            signer_id: d(10),
            plan_digest: plan.plan_digest,
            target_state_root: projection.target_state_root,
            target_genesis_id: plan.target_genesis_id,
            signature_digest: d(11),
        };
        let second = CutoverAttestationV0 {
            signer_id: d(12),
            plan_digest: plan.plan_digest,
            target_state_root: projection.target_state_root,
            target_genesis_id: plan.target_genesis_id,
            signature_digest: d(13),
        };
        let a = verify_cutover_agreement_v0(&WeightOne, &projection, 2, &[first, second]).unwrap();
        let b = verify_cutover_agreement_v0(&WeightOne, &projection, 2, &[second, first]).unwrap();
        assert_eq!(a.signer_set_digest, b.signer_set_digest);
        assert_eq!(a.agreement_digest, b.agreement_digest);
    }

    #[test]
    fn durable_handoff_transitions_atomically_and_rejects_stale_mutation() {
        let (rows, export, plan) = verified_fixture();
        let binding = export.source_binding_v0();
        let source_raw = SourceCheckpointContextV0 {
            chain_id: d(1),
            protocol_digest: d(2),
            checkpoint_digest: d(10),
            block_id: d(11),
            height: 100,
            epoch: 1,
            state_root: d(3),
            validator_set_digest: d(12),
            finality_proof_digest: d(13),
        };
        let source = verify_source_checkpoint_context_v0(&AcceptFinality, source_raw).unwrap();
        let projection =
            project_and_recompute_v0(&plan, &export, &rows, &IdentityProjector, &HashRoot).unwrap();
        let target_raw = SourceCheckpointContextV0 {
            chain_id: d(1),
            protocol_digest: d(2),
            checkpoint_digest: d(14),
            block_id: d(15),
            height: 101,
            epoch: 1,
            state_root: projection.target_state_root,
            validator_set_digest: d(16),
            finality_proof_digest: d(17),
        };
        let target = verify_source_checkpoint_context_v0(&AcceptFinality, target_raw).unwrap();
        let path = std::env::temp_dir().join(format!(
            "trnm-migration-handoff-{}-{}.sqlite",
            std::process::id(),
            d(201).0[0]
        ));
        let _ = std::fs::remove_file(&path);
        let record =
            MigrationHandoffRecordV0::new_verified_source(&plan, &binding, &source, 99).unwrap();
        let store = SqliteMigrationHandoffStoreV0::initialize(&path, record).unwrap();
        assert_eq!(
            store.readback_v0().unwrap().state,
            MigrationHandoffStateV0::VerifiedSource
        );
        let projected = store
            .projected_delta_v0(&projection, &source, &target)
            .unwrap();
        assert_eq!(projected.state, MigrationHandoffStateV0::ProjectedDelta);
        let readback = DurableDeltaReadbackV0 {
            plan_digest: plan.plan_digest,
            target_schema_digest: plan.target_schema_digest,
            source_context_digest: source_raw.canonical_digest(),
            target_context_digest: target_raw.canonical_digest(),
            rows_digest: projection.target_rows_digest,
            state_root: projection.target_state_root,
            row_count: projection.target_row_count,
            generation: 1,
            last_delta_digest: d(202),
        };
        let receipt = DurableDeltaInstallReceiptV0 {
            previous_root: d(3),
            installed_root: projection.target_state_root,
            generation: 1,
            delta_digest: d(202),
        };
        let mut substituted_readback = readback.clone();
        substituted_readback.rows_digest = d(206);
        assert!(matches!(
            store.durable_install_v0(d(204), receipt, substituted_readback),
            Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::DurableReadbackMismatch
            ))
        ));
        assert_eq!(
            store.readback_v0().unwrap().state,
            MigrationHandoffStateV0::ProjectedDelta
        );
        store
            .durable_install_v0(d(204), receipt, readback.clone())
            .unwrap();
        assert!(matches!(
            store.runtime_ready_v0([
                MigrationReadinessReceiptV0 {
                    module: MigrationReadinessModuleV0::M01,
                    receipt_digest: d(1)
                },
                MigrationReadinessReceiptV0 {
                    module: MigrationReadinessModuleV0::M02,
                    receipt_digest: d(2)
                },
                MigrationReadinessReceiptV0 {
                    module: MigrationReadinessModuleV0::M08,
                    receipt_digest: d(8)
                },
            ]),
            Err(MigrationHandoffErrorV0::Protocol(
                MigrationErrorV0::InvalidHandoffTransition
            ))
        ));
        assert_eq!(
            store.readback_v0().unwrap().state,
            MigrationHandoffStateV0::DurableInstall
        );
        store.readback_cas_v0(readback).unwrap();
        let agreement_digest = Digest32V0::hash(
            b"trnm.migration.cutover-agreement.v0",
            &[
                &plan.plan_digest.0,
                &projection.target_state_root.0,
                &plan.target_genesis_id.0,
                &2_u64.to_be_bytes(),
                &2_u64.to_be_bytes(),
                &d(205).0,
            ],
        );
        store
            .cutover_agreed_v0(CutoverAgreementV0 {
                plan_digest: plan.plan_digest,
                target_state_root: projection.target_state_root,
                target_genesis_id: plan.target_genesis_id,
                signed_weight: 2,
                required_weight: 2,
                signer_set_digest: d(205),
                agreement_digest,
            })
            .unwrap();
        let ready = store
            .runtime_ready_v0([
                MigrationReadinessReceiptV0 {
                    module: MigrationReadinessModuleV0::M01,
                    receipt_digest: d(1),
                },
                MigrationReadinessReceiptV0 {
                    module: MigrationReadinessModuleV0::M02,
                    receipt_digest: d(2),
                },
                MigrationReadinessReceiptV0 {
                    module: MigrationReadinessModuleV0::M08,
                    receipt_digest: d(8),
                },
            ])
            .unwrap();
        assert_eq!(ready.state, MigrationHandoffStateV0::RuntimeReady);
        assert_eq!(
            SqliteMigrationHandoffStoreV0::open_existing(&path)
                .unwrap()
                .readback_v0()
                .unwrap(),
            ready
        );
        let _ = std::fs::remove_file(path);
    }
}
