#![forbid(unsafe_code)]
//! Finalized-export to fresh-genesis migration core.
//!
//! This crate intentionally has no database rewrite path and no validator
//! signing-state import API.  It verifies an exact finalized source export,
//! projects rows into a target schema, recomputes the target root through an
//! injected canonical builder, and binds cutover agreement to a no-fallback
//! plan.

use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, error::Error, fmt};

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
pub struct VerifiedExportV0 {
    pub header: FinalizedExportHeaderV0,
    pub ordered_rows_digest: Digest32V0,
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

/// Verify and apply one authenticated delta to an exact base state.  Every
/// key/value and both roots are recomputed before a target vector is returned.
pub fn apply_incremental_delta_v0<R>(
    delta: &IncrementalStateDeltaV0,
    base_rows: &[TargetRowV0],
    root_builder: &R,
) -> Result<Vec<TargetRowV0>, IncrementalDeltaErrorV0<R::Error>>
where
    R: TargetRootBuilderV0,
{
    delta
        .validate()
        .map_err(IncrementalDeltaErrorV0::Protocol)?;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationErrorV0 {
    InvalidExportRow,
    ForbiddenAuthorityState,
    InvalidExportHeader,
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
    DeltaRootMismatch,
    DeltaRowsOutOfBounds,
    TargetRowsOutOfBounds,
    BaseStateMismatch,
    TargetStateMismatch,
}

impl fmt::Display for MigrationErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidExportRow => "invalid source export row",
            Self::ForbiddenAuthorityState => "validator or node authority state cannot be migrated",
            Self::InvalidExportHeader => "invalid finalized export header",
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
            Self::DeltaRootMismatch => "incremental delta root mismatch",
            Self::DeltaRowsOutOfBounds => "incremental delta exceeds its row bound",
            Self::TargetRowsOutOfBounds => "target state exceeds its row bound",
            Self::BaseStateMismatch => "incremental delta base state mismatch",
            Self::TargetStateMismatch => "incremental delta target state mismatch",
        })
    }
}

impl Error for MigrationErrorV0 {}

#[derive(Debug)]
pub enum MigrationHostErrorV0<AdapterError> {
    Protocol(MigrationErrorV0),
    SourceFinality(AdapterError),
    CutoverSignature(AdapterError),
}

impl<A: fmt::Display> fmt::Display for MigrationHostErrorV0<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "migration protocol rejected input: {error}"),
            Self::SourceFinality(error) => {
                write!(f, "source finality verification failed: {error}")
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

    #[test]
    fn incremental_delta_recomputes_and_applies_exact_state() {
        let base = vec![target_row(1, 10), target_row(2, 20), target_row(4, 40)];
        let target = vec![target_row(2, 21), target_row(3, 30), target_row(4, 40)];
        let delta = derive_incremental_delta_v0(d(90), d(91), &base, &target, &HashRoot).unwrap();
        assert_eq!(
            delta.entries.len(),
            3,
            "delete, insert and update are distinct operations"
        );
        assert_eq!(delta.base_row_count, 3);
        assert_eq!(delta.target_row_count, 3);
        assert_eq!(
            apply_incremental_delta_v0(&delta, &base, &HashRoot).unwrap(),
            target
        );
    }

    #[test]
    fn incremental_delta_rejects_base_substitution_and_entry_tampering() {
        let base = vec![target_row(1, 10), target_row(2, 20)];
        let target = vec![target_row(1, 11), target_row(2, 20)];
        let delta = derive_incremental_delta_v0(d(92), d(93), &base, &target, &HashRoot).unwrap();
        let mut substituted = base.clone();
        substituted[0].value[0] = 99;
        assert!(matches!(
            apply_incremental_delta_v0(&delta, &substituted, &HashRoot),
            Err(IncrementalDeltaErrorV0::Protocol(
                MigrationErrorV0::BaseStateMismatch
            ))
        ));

        let mut tampered = delta.clone();
        tampered.entries[0].value = Some(vec![77]);
        assert!(matches!(
            apply_incremental_delta_v0(&tampered, &base, &HashRoot),
            Err(IncrementalDeltaErrorV0::Protocol(
                MigrationErrorV0::InvalidDeltaRow
            ))
        ));
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
}
