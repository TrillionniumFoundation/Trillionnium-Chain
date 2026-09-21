//! Explicit schema-4 bridge. No schema migration is performed by ordinary open.
//! Frozen v0 rows remain immutable; sparse-history executions use a separate P.
use super::*;
use crate::epoch_edge::EpochExecutionContextV1;
use crate::epoch_recovery::{EpochRecoveryEvidenceV1, MAX_EPOCH_EVIDENCE_BYTES_V1};
use anyhow::Result;
use trnm_consensus_types::BlockKind;
use trnm_native_application::{NativeEpochBlockExecutionRequestV1, NativeExecutedEpochBlockV1};

pub(super) const SCHEMA_VERSION: u64 = 4;
/// Versioned later-edge/finality storage.  The original schema-4 rows remain
/// byte-for-byte compatible; this version is entered only by the explicit
/// migration below and is never selected by ordinary open.
pub(super) const LEGACY_LATER_SCHEMA_VERSION: u64 = 8;
pub(super) const APPLICATION_FINALITY_SCHEMA_VERSION: u64 = 9;
pub(super) const LATER_SCHEMA_VERSION: u64 = 10;
pub(super) const PRE_HANDOFF_SCHEMA_VERSION: u64 = 13;
#[path = "later_epoch_pre_handoff_v1.rs"]
mod pre_handoff;
pub use pre_handoff::CommittedLaterEpochPreHandoffV1;
#[path = "later_epoch_selection_v1.rs"]
mod later_selection;
pub use later_selection::ComputedLaterEpochSelectionV1;
pub(super) const PRE_HANDOFF_SCHEMA: (&str, &str) = pre_handoff::SCHEMA;
#[path = "later_epoch_descendant_finality_v1.rs"]
mod descendant_finality;
#[path = "historical_replay_owner_v1.rs"]
pub(super) mod historical_replay;
#[path = "epoch_lineage_v1.rs"]
mod lineage_resolver;
pub use historical_replay::{
    CommittedNativeReplayExecutionV1, ConfirmedNativeReplayAnchorV1, ConfirmedNativeReplayBaseV1,
    ConfirmedPreparedNativeReplayExecutionV1, PreparedNativeReplayBaseV1,
};
#[path = "native_live_export_v1.rs"]
mod live_export;
#[path = "epoch_sync_export_v1.rs"]
mod sync_export;
pub use sync_export::{
    NativeEpochFinalityPathV1, NativeEpochFinalityStepV1, NativeHistoricalRecordV1,
    NativeHistoricalReplayV1,
};
const MAX_P_ROWS: usize = 128;
const MAX_PREPARED_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
const MAX_REPLAY_BYTES: usize = 16 * 1024 * 1024;
const MAX_LIFECYCLE_BYTES: usize = 1024 * 1024;
const MAX_EDGES: usize = 32;
const MAX_HEADER_BYTES: usize = 4096;
const MAX_SET_BYTES: usize = 1024 * 1024;
const MAX_PARAMETERS_BYTES: usize = 4096;

/// Read interpretation for retained source data.  This is an audit selector,
/// never an authority or migration permit.  Physical callers continue to use
/// the live metadata schema; the installer path may explicitly interpret the
/// preserved source tables as schema10 while the surrounding database is a
/// newer physical schema.
#[derive(Clone, Copy)]
pub(super) enum EpochReadPolicyV1<'a> {
    Physical,
    RetainedSource10(&'a MetadataV0),
}

impl EpochReadPolicyV1<'_> {
    pub(super) fn schema(self, connection: &Connection) -> DurableResult<u64> {
        match self {
            Self::Physical => schema_version(connection),
            Self::RetainedSource10(_) => Ok(LATER_SCHEMA_VERSION),
        }
    }

    pub(super) fn head(
        self,
        connection: &Connection,
        config: &NativeApplicationConfigV0,
    ) -> DurableResult<ApplicationHeadV0> {
        match self {
            Self::Physical => {
                super::load_metadata_v0(connection, config).map(|metadata| metadata.head)
            }
            Self::RetainedSource10(metadata) => Ok(metadata.head.clone()),
        }
    }
}

pub(super) const SCHEMA: &[(&str, &str)] = &[
    ("native_epoch_edge_v1", "CREATE TABLE native_epoch_edge_v1 (
       binding BLOB PRIMARY KEY CHECK(length(binding)=32),
       store_id BLOB NOT NULL CHECK(length(store_id)=32),
       checkpoint_height BLOB NOT NULL CHECK(length(checkpoint_height)=8),
       checkpoint_block BLOB NOT NULL CHECK(length(checkpoint_block)=32),
       checkpoint_root BLOB NOT NULL CHECK(length(checkpoint_root)=32),
       checkpoint_commit_id BLOB NOT NULL CHECK(length(checkpoint_commit_id)=32),
       checkpoint_p_digest BLOB NOT NULL CHECK(length(checkpoint_p_digest)=32),
       checkpoint_commit_sequence BLOB NOT NULL CHECK(length(checkpoint_commit_sequence)=8),
       terminal_height BLOB NOT NULL CHECK(length(terminal_height)=8),
       terminal_block BLOB NOT NULL CHECK(length(terminal_block)=32),
       first_height BLOB NOT NULL CHECK(length(first_height)=8),
       evidence BLOB NOT NULL, evidence_digest BLOB NOT NULL CHECK(length(evidence_digest)=32),
       phase INTEGER NOT NULL CHECK(phase IN (0,1)),
       consumed_block BLOB, consumed_sequence BLOB,
       CHECK((phase=0 AND consumed_block IS NULL AND consumed_sequence IS NULL) OR
         (phase=1 AND length(consumed_block)=32 AND length(consumed_sequence)=8))
     )"),
    ("native_durable_execution_p_v1", "CREATE TABLE native_durable_execution_p_v1 (
       block_id BLOB PRIMARY KEY CHECK(length(block_id)=32),
       store_id BLOB NOT NULL CHECK(length(store_id)=32),
       p_sequence BLOB NOT NULL UNIQUE CHECK(length(p_sequence)=8),
       status INTEGER NOT NULL CHECK(status IN (0,1)),
       artifact_kind INTEGER NOT NULL CHECK(artifact_kind IN (0,1)),
       artifact BLOB NOT NULL, artifact_digest BLOB NOT NULL CHECK(length(artifact_digest)=32),
       header BLOB NOT NULL,
       parent_kind INTEGER NOT NULL CHECK(parent_kind IN (0,1)),
       parent_height BLOB NOT NULL CHECK(length(parent_height)=8),
       parent_block BLOB NOT NULL CHECK(length(parent_block)=32),
       parent_root BLOB NOT NULL CHECK(length(parent_root)=32),
       parent_commit_id BLOB NOT NULL CHECK(length(parent_commit_id)=32),
       parent_p_digest BLOB,
       consensus_parent_height BLOB NOT NULL CHECK(length(consensus_parent_height)=8),
       consensus_parent_block BLOB NOT NULL CHECK(length(consensus_parent_block)=32),
       target_height BLOB NOT NULL CHECK(length(target_height)=8),
       edge_lineage BLOB NOT NULL, lineage_digest BLOB NOT NULL CHECK(length(lineage_digest)=32),
       target_snapshot BLOB NOT NULL, snapshot_digest BLOB NOT NULL CHECK(length(snapshot_digest)=32),
       replay_commands BLOB NOT NULL, replay_nonces BLOB NOT NULL, lifecycle BLOB NOT NULL,
       target_set BLOB NOT NULL, target_parameters BLOB NOT NULL,
       p_digest BLOB NOT NULL CHECK(length(p_digest)=32),
       commit_sequence BLOB, commit_id BLOB,
       CHECK((parent_kind=0 AND parent_p_digest IS NULL) OR (parent_kind=1 AND length(parent_p_digest)=32)),
       CHECK((status=0 AND commit_sequence IS NULL AND commit_id IS NULL) OR
         (status=1 AND length(commit_sequence)=8 AND length(commit_id)=32))
     )"),
    ("native_application_epoch_context_v1", "CREATE TABLE native_application_epoch_context_v1 (
       singleton INTEGER PRIMARY KEY CHECK(singleton=1),
       store_id BLOB NOT NULL CHECK(length(store_id)=32),
       head_block BLOB NOT NULL CHECK(length(head_block)=32),
       head_root BLOB NOT NULL CHECK(length(head_root)=32),
       head_commit_id BLOB NOT NULL CHECK(length(head_commit_id)=32),
       head_height BLOB NOT NULL CHECK(length(head_height)=8),
       head_commit_sequence BLOB NOT NULL CHECK(length(head_commit_sequence)=8),
       active_set BLOB NOT NULL, active_parameters BLOB NOT NULL,
       edge_lineage BLOB NOT NULL, context_digest BLOB NOT NULL CHECK(length(context_digest)=32)
     )"),
];

pub(super) const LATER_SCHEMA: &[(&str, &str)] = &[
    (
        "native_later_epoch_finality_v1",
        "CREATE TABLE native_later_epoch_finality_v1 (
       checkpoint_block BLOB PRIMARY KEY CHECK(length(checkpoint_block)=32),
       p_digest BLOB NOT NULL CHECK(length(p_digest)=32),
       commit_sequence BLOB NOT NULL CHECK(length(commit_sequence)=8),
       context_digest BLOB NOT NULL CHECK(length(context_digest)=32),
       predecessor_edge BLOB NOT NULL CHECK(length(predecessor_edge)=32),
       checkpoint_parent_header BLOB NOT NULL,
       checkpoint_header BLOB NOT NULL,
       checkpoint_finality BLOB NOT NULL,
       anchor_kernel BLOB NOT NULL,
       next_epoch_commitment BLOB NOT NULL,
       new_validator_set BLOB NOT NULL,
       new_parameters BLOB NOT NULL,
       record_digest BLOB NOT NULL CHECK(length(record_digest)=32)
     )",
    ),
    (
        "native_later_epoch_edge_v1",
        "CREATE TABLE native_later_epoch_edge_v1 (
       successor_binding BLOB PRIMARY KEY CHECK(length(successor_binding)=32),
       predecessor_edge BLOB NOT NULL UNIQUE CHECK(length(predecessor_edge)=32),
       checkpoint_block BLOB NOT NULL UNIQUE CHECK(length(checkpoint_block)=32),
       checkpoint_p_digest BLOB NOT NULL CHECK(length(checkpoint_p_digest)=32),
       checkpoint_commit_sequence BLOB NOT NULL CHECK(length(checkpoint_commit_sequence)=8),
       checkpoint_height BLOB NOT NULL CHECK(length(checkpoint_height)=8),
       checkpoint_root BLOB NOT NULL CHECK(length(checkpoint_root)=32),
       checkpoint_commit_id BLOB NOT NULL CHECK(length(checkpoint_commit_id)=32),
       terminal_height BLOB NOT NULL CHECK(length(terminal_height)=8),
       terminal_block BLOB NOT NULL CHECK(length(terminal_block)=32),
       first_height BLOB NOT NULL CHECK(length(first_height)=8),
       proof_context_digest BLOB NOT NULL CHECK(length(proof_context_digest)=32),
       successor_context_digest BLOB NOT NULL CHECK(length(successor_context_digest)=32),
       authority_digest BLOB NOT NULL CHECK(length(authority_digest)=32),
       phase INTEGER NOT NULL CHECK(phase IN (0,1)),
       consumed_block BLOB,
       consumed_sequence BLOB,
       record_digest BLOB NOT NULL CHECK(length(record_digest)=32),
       CHECK((phase=0 AND consumed_block IS NULL AND consumed_sequence IS NULL) OR
         (phase=1 AND length(consumed_block)=32 AND length(consumed_sequence)=8))
     )",
    ),
    (
        "native_later_epoch_application_finality_v1",
        "CREATE TABLE native_later_epoch_application_finality_v1 (
       block_id BLOB PRIMARY KEY CHECK(length(block_id)=32),
       p_digest BLOB NOT NULL CHECK(length(p_digest)=32),
       commit_sequence BLOB NOT NULL CHECK(length(commit_sequence)=8),
       edge_binding BLOB NOT NULL CHECK(length(edge_binding)=32),
       proof BLOB NOT NULL,
       proof_digest BLOB NOT NULL CHECK(length(proof_digest)=32),
       record_digest BLOB NOT NULL CHECK(length(record_digest)=32)
     )",
    ),
    descendant_finality::SCHEMA,
];

/// Exact schema-8 shape retained for explicit migration.  The
/// application-finality proof ledger did not exist in schema 8.
pub(super) const LATER_SCHEMA_V8: &[(&str, &str)] = &[LATER_SCHEMA[0], LATER_SCHEMA[1]];
/// Frozen schema-9 inventory; ordinary descendant proofs first appear in 10.
pub(super) const LATER_SCHEMA_V9: &[(&str, &str)] =
    &[LATER_SCHEMA[0], LATER_SCHEMA[1], LATER_SCHEMA[2]];

pub(super) const fn is_epoch_schema(version: u64) -> bool {
    version == SCHEMA_VERSION
        || version == LEGACY_LATER_SCHEMA_VERSION
        || version == APPLICATION_FINALITY_SCHEMA_VERSION
        || version == LATER_SCHEMA_VERSION
        || version == PRE_HANDOFF_SCHEMA_VERSION
}

pub(super) const fn has_later_schema(version: u64) -> bool {
    version == LEGACY_LATER_SCHEMA_VERSION
        || version == APPLICATION_FINALITY_SCHEMA_VERSION
        || version == LATER_SCHEMA_VERSION
        || version == PRE_HANDOFF_SCHEMA_VERSION
}

pub(super) const fn has_later_application_finality_schema(version: u64) -> bool {
    version == APPLICATION_FINALITY_SCHEMA_VERSION
        || version == LATER_SCHEMA_VERSION
        || version == PRE_HANDOFF_SCHEMA_VERSION
}

pub(super) const fn has_later_descendant_finality_schema(version: u64) -> bool {
    version == LATER_SCHEMA_VERSION || version == PRE_HANDOFF_SCHEMA_VERSION
}

#[derive(Debug, Clone)]
struct StoredEpochPV1 {
    store_id: [u8; 32],
    p_sequence: u64,
    status: i64,
    artifact_kind: i64,
    artifact: Vec<u8>,
    artifact_digest: [u8; 32],
    header: Vec<u8>,
    parent_kind: i64,
    parent: ApplicationHeadV0,
    parent_p_digest: Option<[u8; 32]>,
    consensus_parent_height: u64,
    consensus_parent_block: [u8; 32],
    target_height: u64,
    block_id: [u8; 32],
    lineage: Vec<u8>,
    lineage_digest: [u8; 32],
    snapshot: Vec<u8>,
    snapshot_digest: [u8; 32],
    commands: Vec<u8>,
    nonces: Vec<u8>,
    lifecycle: Vec<u8>,
    target_set: Vec<u8>,
    target_parameters: Vec<u8>,
    p_digest: [u8; 32],
    commit_sequence: Option<u64>,
    commit_id: Option<[u8; 32]>,
}

/// Fresh, authenticated readback of one committed schema-4 ordinary
/// descendant.  This is deliberately a separate carrier from the frozen-v0
/// read API: schema-4 checkpoint/handoff artifacts do not yet have a public
/// finalized-read bridge and therefore cannot be returned here.
#[derive(Debug)]
#[must_use = "the schema-4 finalized read must remain joined to its owner"]
pub struct FinalizedNativeEpochApplicationReadV1 {
    owner: Arc<()>,
    confirmed_head: ApplicationHeadV0,
    row: StoredEpochPV1,
    executed: NativeExecutedBlockV0,
    receipt_commitments: Vec<Hash32V0>,
    coordinates: Vec<crate::epoch_edge::EpochApplicationCoordinatesV1>,
}

impl FinalizedNativeEpochApplicationReadV1 {
    /// Fixture-only immutable candidate-selection facts from this real audited
    /// cutoff. This issues no preparation, activation, signing or apply authority.
    #[cfg(feature = "test-fixtures")]
    pub fn test_fixture_next_epoch_facts_v1(
        &self,
        application: &DurableNativeApplicationV0,
    ) -> Result<(
        ValidatorSet,
        ConsensusParametersV0,
        trnm_consensus_types::NextEpochCommitmentV0,
    )> {
        let computed = self.derive_next_epoch_v1(application)?;
        Ok((
            computed.new_validator_set,
            computed.new_parameters,
            computed.commitment,
        ))
    }

    /// Pure computation from this already audited cutoff. No preparation or
    /// activation authority is issued; consumers still join the exact result.
    pub(crate) fn derive_next_epoch_v1(
        &self,
        application: &DurableNativeApplicationV0,
    ) -> Result<crate::poco_application::ComputedPocoNextEpochV1> {
        ensure!(
            Arc::ptr_eq(&self.owner, &application.owner_affinity),
            "cutoff computation foreign owner"
        );
        derive_poco_next_epoch_from_cutoff_p_v1(&application.config, &self.row, &self.coordinates)
    }

    /// The freshly validated application head observed in the same read.
    pub const fn confirmed_head_v1(&self) -> &ApplicationHeadV0 {
        &self.confirmed_head
    }

    /// The exact target head represented by the committed schema-4 P row.
    pub fn finalized_head_v1(&self) -> Result<ApplicationHeadV0> {
        self.row.target_head()
    }

    /// The canonical ordinary execution artifact decoded from the P row.
    pub const fn executed_v1(&self) -> &NativeExecutedBlockV0 {
        &self.executed
    }

    /// Per-transaction receipt commitments in canonical transaction order.
    pub fn receipt_commitments_v1(&self) -> &[Hash32V0] {
        &self.receipt_commitments
    }

    pub const fn p_digest_v1(&self) -> [u8; 32] {
        self.row.p_digest
    }

    pub const fn commit_sequence_v1(&self) -> Option<u64> {
        self.row.commit_sequence
    }

    pub const fn artifact_digest_v1(&self) -> [u8; 32] {
        self.row.artifact_digest
    }

    /// Confirms that this carrier belongs to the same live owner and exact
    /// path, then repeats the authenticated height read to close a stale-read
    /// window.  A reopened owner intentionally fails the affinity check.
    pub fn belongs_to_application_at_path_v1(
        &self,
        application: &DurableNativeApplicationV0,
        expected_path: &Path,
    ) -> bool {
        Arc::ptr_eq(&self.owner, &application.owner_affinity)
            && application.path() == expected_path
            && application
                .read_finalized_by_height_v1(HeightV0::new(self.row.target_height))
                .is_ok_and(|fresh| {
                    fresh.row.p_digest == self.row.p_digest
                        && fresh.row.commit_sequence == self.row.commit_sequence
                        && fresh.row.artifact_digest == self.row.artifact_digest
                })
    }
}

/// Actual persisted P, owner-affine and private-construction. The prospective
/// head is a speculative parent identity, never a committed receipt.
#[must_use]
pub struct PreparedNativeEpochExecutionV1 {
    owner: Arc<()>,
    row: StoredEpochPV1,
}
impl PreparedNativeEpochExecutionV1 {
    pub fn header(&self) -> Result<BlockHeader> {
        decode_header(&self.row.header)
    }
    pub fn application_parent(&self) -> &ApplicationHeadV0 {
        &self.row.parent
    }
    pub const fn consensus_parent_height(&self) -> u64 {
        self.row.consensus_parent_height
    }
    pub const fn consensus_parent_id(&self) -> [u8; 32] {
        self.row.consensus_parent_block
    }
    pub const fn p_digest(&self) -> [u8; 32] {
        self.row.p_digest
    }
    pub const fn persist_sequence(&self) -> u64 {
        self.row.p_sequence
    }
    pub const fn artifact_digest(&self) -> [u8; 32] {
        self.row.artifact_digest
    }
    pub fn overlay_parent_head(&self) -> Result<ApplicationHeadV0> {
        self.row.target_head()
    }
}

/// Fresh exact P and strict retained-edge reconstruction, never a Core permit.
/// ```compile_fail
/// use trnm_native_execution_v0::ConfirmedPreparedNativeEpochExecutionV1;
/// fn copy_receipt(receipt: ConfirmedPreparedNativeEpochExecutionV1) {
///     let duplicate = receipt.clone();
/// }
/// ```
#[must_use]
pub struct ConfirmedPreparedNativeEpochExecutionV1 {
    prepared: PreparedNativeEpochExecutionV1,
}
impl ConfirmedPreparedNativeEpochExecutionV1 {
    pub fn prepared(&self) -> &PreparedNativeEpochExecutionV1 {
        &self.prepared
    }
    pub const fn artifact_checksum(&self) -> [u8; 32] {
        self.prepared.row.artifact_digest
    }
    pub const fn overlay_checksum(&self) -> [u8; 32] {
        self.prepared.row.snapshot_digest
    }
    pub const fn commit_sequence(&self) -> Option<u64> {
        self.prepared.row.commit_sequence
    }
    pub fn application_payload_and_receipts(
        &self,
    ) -> Result<(
        trnm_consensus_types::ApplicationPayloadV0,
        trnm_consensus_types::ExecutionReceiptsV0,
    )> {
        let row = &self.prepared.row;
        let exact = if row.artifact_kind == 1 {
            let executed = trnm_native_application::decode_native_executed_epoch_block_artifact_v1(
                &row.artifact,
            )?;
            crate::poco_checkpoint::native_execution_from_receipts_v0(
                executed.request().preview().transactions(),
                executed.receipts(),
            )?
        } else {
            let executed = decode_native_executed_block_artifact_v0(&row.artifact)?;
            crate::poco_checkpoint::native_execution_from_receipts_v0(
                executed.request().transactions(),
                executed.receipts(),
            )?
        };
        Ok((
            exact.application_payload().clone(),
            exact.execution_receipts().clone(),
        ))
    }
    pub fn belongs_to_application_at_path(
        &self,
        app: &DurableNativeApplicationV0,
        expected_path: &Path,
    ) -> bool {
        app.path() == expected_path
            && app
                .confirm_prepared_epoch_execution_v1(&self.prepared)
                .is_ok_and(|fresh| {
                    fresh.prepared.row.status == self.prepared.row.status
                        && fresh.commit_sequence() == self.commit_sequence()
                })
    }
}

impl StoredEpochPV1 {
    fn target_head(&self) -> Result<ApplicationHeadV0> {
        let header = decode_header(&self.header)?;
        Ok(ApplicationHeadV0::new(
            HeightV0::new(self.target_height),
            BlockIdV0::new(self.block_id)?,
            StateRootV0::new(*header.state_root().as_bytes())?,
            ApplicationCommitIdV0::new(self.commit_identity())?,
        ))
    }
    fn commit_identity(&self) -> [u8; 32] {
        hash_domain(
            "trnm.native-application.commit-id.v1",
            &[&self.p_digest, &self.block_id, &self.snapshot_digest],
        )
    }
    fn digest(&self) -> Result<[u8; 32]> {
        let set = trnm_consensus_types::decode_validator_set_v0_exact(&self.target_set)
            .map_err(|e| anyhow::anyhow!("P target set: {e:?}"))?;
        let parameters =
            trnm_consensus_types::decode_consensus_parameters_v0_exact(&self.target_parameters)
                .map_err(|e| anyhow::anyhow!("P target parameters: {e:?}"))?;
        let optional = match self.parent_p_digest {
            None => vec![0],
            Some(id) => [&[1u8][..], &id].concat(),
        };
        Ok(hash_domain(
            "trnm.native-application.durable-p.v1",
            &[
                &self.store_id,
                &self.p_sequence.to_be_bytes(),
                &[self.artifact_kind as u8],
                &self.artifact_digest,
                &[self.parent_kind as u8],
                &self.parent.height().get().to_be_bytes(),
                self.parent.block_id().as_bytes(),
                self.parent.state_root().as_bytes(),
                self.parent.commit_id().as_bytes(),
                &optional,
                &self.consensus_parent_height.to_be_bytes(),
                &self.consensus_parent_block,
                &self.target_height.to_be_bytes(),
                &self.lineage_digest,
                &self.snapshot_digest,
                &sha256_v0(&self.commands),
                &sha256_v0(&self.nonces),
                &sha256_v0(&self.lifecycle),
                set.id().as_bytes(),
                parameters.hash().as_bytes(),
                &sha256_v0(&self.header),
            ],
        ))
    }
}

fn decode_header(bytes: &[u8]) -> Result<BlockHeader> {
    trnm_consensus_types::decode_block_header_v0_exact(bytes)
        .map_err(|e| anyhow::anyhow!("epoch P header: {e:?}"))
}

/// The selected cutoff P and coordinates belong to an already audited prefix.
/// Decode its authenticated state directly; never re-enter prefix/P inventory.
fn derive_poco_next_epoch_from_cutoff_p_v1(
    config: &NativeApplicationConfigV0,
    cutoff: &StoredEpochPV1,
    coordinates: &[crate::epoch_edge::EpochApplicationCoordinatesV1],
) -> Result<crate::poco_application::ComputedPocoNextEpochV1> {
    let header = decode_header(&cutoff.header)?;
    ensure!(
        cutoff.status == 1
            && cutoff.artifact_kind == 0
            && header.block_kind() == BlockKind::Regular
            && header.height().get() == cutoff.target_height
            && cutoff.store_id == config.store_id
            && cutoff.snapshot_digest == sha256_v0(&cutoff.snapshot),
        "candidate cutoff P identity"
    );
    let set = trnm_consensus_types::decode_validator_set_v0_exact(&cutoff.target_set)
        .map_err(|e| anyhow::anyhow!("candidate cutoff set: {e:?}"))?;
    let parameters =
        trnm_consensus_types::decode_consensus_parameters_v0_exact(&cutoff.target_parameters)
            .map_err(|e| anyhow::anyhow!("candidate cutoff parameters: {e:?}"))?;
    ensure!(
        header.validator_set_id() == set.id()
            && header.consensus_parameters_hash() == parameters.hash(),
        "candidate cutoff header configuration"
    );
    let store = InMemoryNativeExecutionStoreV0::decode_epoch_snapshot_for_coordinates_v1(
        config.chain_id.clone(),
        config.signers.clone(),
        parameters,
        decode_borsh_v0(&cutoff.commands, "candidate cutoff commands")?,
        decode_borsh_v0(&cutoff.nonces, "candidate cutoff nonces")?,
        &cutoff.snapshot,
        coordinates,
    )?;
    ensure!(
        store.parent_version_v0()? == header.height().get()
            && store.parent_root_v0()?.0 == *header.state_root().as_bytes(),
        "candidate cutoff authenticated state root"
    );
    let mut live = store.verified_live_values_v0(header.height().get())?;
    let lifecycle = load_validator_lifecycle_from_live_v0(&live, header.height().get())?;
    validate_application_validator_projection_v0(&set, &lifecycle.active_validators)?;
    let projection = crate::poco_transition::take_and_validate_production_poco_projection_v0(
        header.height().get(),
        &mut live,
    )?
    .context("candidate cutoff PoCO namespace missing")?;
    crate::poco_application::derive_poco_next_epoch_from_cutoff_v1(
        &projection,
        header.state_root(),
        &set,
        &parameters,
    )
}

fn local_error(_: impl std::fmt::Display) -> NativeApplicationExecutionErrorV0 {
    error(
        NativeApplicationExecutionErrorCodeV0::CorruptStore,
        "epoch_bridge.audit",
    )
}

pub(super) fn schema_version(connection: &Connection) -> DurableResult<u64> {
    let value: [u8; 8] = connection
        .query_row(
            "SELECT schema_version FROM native_application_metadata_v0 WHERE singleton=1",
            [],
            |r| match r.get_ref(0)? {
                rusqlite::types::ValueRef::Blob(bytes) => {
                    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
                }
                _ => Err(rusqlite::Error::InvalidQuery),
            },
        )
        .map_err(|_| {
            error(
                NativeApplicationExecutionErrorCodeV0::Storage,
                "epoch_bridge.schema",
            )
        })?;
    decode_u64_v0(&value, "epoch_bridge.schema")
}

impl DurableNativeApplicationV0 {
    /// Recover the current later checkpoint after an uncertain commit or a
    /// process restart. Revalidates retained signatures and every native join
    /// before returning a receipt affiliated with this newly opened owner.
    pub fn recover_later_epoch_checkpoint_commit_v1(
        &self,
        checkpoint_block: [u8; 32],
    ) -> Result<CommittedNativeEpochExecutionV1> {
        let _guard = self.lock_operation()?;
        sync_store_commit_boundary_v0(&self.path)?;
        let metadata = fresh_validate_v0(&self.path, &self.config)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        ensure!(
            has_later_schema(schema_version(&connection)?),
            "later recovery requires schema8"
        );
        let p = load_p(&connection, &checkpoint_block)?.context("later recovery P missing")?;
        validate_p(&connection, &self.config, &p)?;
        ensure!(
            p.status == 1
                && p.target_head()? == metadata.head
                && decode_header(&p.header)?.block_kind() == BlockKind::EpochCheckpoint,
            "later recovery requires current committed checkpoint"
        );
        let sequence = p
            .commit_sequence
            .context("later recovery sequence missing")?;
        ensure!(
            fresh_validate_v0(&self.path, &self.config)? == metadata,
            "later recovery changed during readback"
        );
        Ok(CommittedNativeEpochExecutionV1 {
            owner: Arc::clone(&self.owner_affinity),
            head: p.target_head()?,
            p_digest: p.p_digest,
            commit_sequence: sequence,
        })
    }

    /// Commit a strictly verified later-epoch checkpoint through the explicit
    /// schema-8 ledger.  The checkpoint is an application block (its seals
    /// remain consensus-only), so the P/metadata/context update and the
    /// proof record are one SQLite transaction followed by the normal fsync
    /// and immutable readback barriers.
    pub fn commit_later_epoch_checkpoint_finality_v1(
        &self,
        finality: &crate::LaterEpochCheckpointFinalityV1,
    ) -> Result<CommittedNativeEpochExecutionV1> {
        ensure!(finality.has_owner_v1(self), "later finality foreign owner");
        let preimages = finality.durable_preimages_v1()?;
        let block = *finality.checkpoint_header().id().as_bytes();
        let prepared = self.reopen_prepared_epoch_execution_v1(block)?;
        ensure!(
            prepared.row.artifact_kind == 0
                && prepared.header()? == *finality.checkpoint_header()
                && decode_lineage(&prepared.row.lineage)? == finality.lineage(),
            "later checkpoint P/header/lineage binding"
        );
        self.commit_epoch_p(&prepared, Some(&preimages), None, None, None)
    }

    pub fn preview_epoch_descendant_v1(
        &self,
        parent: &PreparedNativeEpochExecutionV1,
        request: &NativeBlockPreviewRequestV0,
    ) -> Result<NativeBlockPreviewV0> {
        ensure!(
            Arc::ptr_eq(&parent.owner, &self.owner_affinity)
                && request.parent() == &parent.overlay_parent_head()?,
            "epoch descendant preview parent/owner mismatch"
        );
        let ids = decode_lineage(&parent.row.lineage)?;
        let contexts = self.recover_epoch_execution_contexts_v1(&ids)?;
        let context = contexts.last().context("parent lineage missing")?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let p =
            load_p(&connection, &parent.row.block_id)?.context("epoch preview parent missing")?;
        ensure!(
            p.p_digest == parent.row.p_digest,
            "epoch preview parent changed"
        );
        let store = validate_p(&connection, &self.config, &p)?;
        preview_complete_native_block_v0(
            &store,
            context.new_validator_set_v1(),
            context.new_validator_set_v1().genesis_hash(),
            request,
        )
    }

    /// Explicit local migration; an ordinary open never performs this action.
    pub fn upgrade_epoch_schema_v1(&self, expected: &ApplicationHeadV0) -> Result<()> {
        let _guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        ensure!(
            &metadata.head == expected,
            "epoch migration predecessor mismatch"
        );
        if is_epoch_schema(schema_version(&connection)?) {
            return Ok(());
        }
        ensure!(
            load_all_p_v0(&connection)?
                .iter()
                .all(|p| p.status == P_STATUS_COMMITTED),
            "epoch migration requires resolved ordinary preparations"
        );
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (_, sql) in SCHEMA {
            tx.execute_batch(sql)?;
        }
        let changed = tx.execute("UPDATE native_application_metadata_v0 SET schema_version=? WHERE singleton=1 AND schema_version=? AND durable_sequence=?",
            params![SCHEMA_VERSION.to_be_bytes().as_slice(), APPLICATION_SCHEMA_VERSION_V0.to_be_bytes().as_slice(), metadata.durable_sequence.to_be_bytes().as_slice()])?;
        ensure!(changed == 1, "epoch migration CAS failed");
        tx.commit()?;
        drop(connection);
        sync_store_commit_boundary_v0(&self.path)?;
        let after = fresh_validate_v0(&self.path, &self.config)?;
        ensure!(
            after == metadata,
            "epoch migration changed application state"
        );
        Ok(())
    }

    /// Explicit migration to schema 10. Existing ordinary later commits cannot
    /// be upgraded: their original finality proof was never retained.
    pub fn upgrade_later_epoch_schema_v1(&self, expected: &ApplicationHeadV0) -> Result<()> {
        let _guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Pin schema, all retained authority and the application head in the
        // same locked snapshot before creating any new table.
        verify_schema_v0(&tx)?;
        let metadata = load_metadata_v0(&tx, &self.config)?;
        validate_metadata_v0(&tx, &self.config, &metadata)?;
        ensure!(
            &metadata.head == expected,
            "later schema migration predecessor mismatch"
        );
        let version = schema_version(&tx)?;
        ensure!(
            is_epoch_schema(version),
            "explicit schema4 later migration required"
        );
        if version == LEGACY_LATER_SCHEMA_VERSION {
            let consumed_edges: i64 = tx.query_row(
                "SELECT COUNT(*) FROM native_later_epoch_edge_v1 WHERE phase=1",
                [],
                |row| row.get(0),
            )?;
            ensure!(
                consumed_edges == 0,
                "schema-8 consumed successor requires retained application finality proof"
            );
        }
        if version == APPLICATION_FINALITY_SCHEMA_VERSION {
            ensure!(
                descendant_finality::committed_blocks(&tx)?.is_empty(),
                "schema-9 committed later descendant requires retained original finality proof"
            );
        }
        ensure!(
            version != PRE_HANDOFF_SCHEMA_VERSION,
            "schema13 cannot downgrade to schema10"
        );
        if version != LATER_SCHEMA_VERSION {
            let existing = match version {
                SCHEMA_VERSION => 0,
                LEGACY_LATER_SCHEMA_VERSION => LATER_SCHEMA_V8.len(),
                APPLICATION_FINALITY_SCHEMA_VERSION => LATER_SCHEMA_V9.len(),
                _ => unreachable!("validated epoch schema"),
            };
            for (_, sql) in &LATER_SCHEMA[existing..] {
                tx.execute_batch(sql)?;
            }
            ensure!(
                tx.execute(
                    "UPDATE native_application_metadata_v0 SET schema_version=?1 WHERE singleton=1 AND schema_version=?2 AND durable_sequence=?3",
                    params![
                        LATER_SCHEMA_VERSION.to_be_bytes().as_slice(),
                        version.to_be_bytes().as_slice(),
                        metadata.durable_sequence.to_be_bytes().as_slice()
                    ],
                )? == 1,
                "later schema migration CAS failed"
            );
        }
        tx.commit()?;
        drop(connection);
        sync_store_commit_boundary_v0(&self.path)?;
        ensure!(
            fresh_validate_v0(&self.path, &self.config)? == metadata,
            "later schema migration changed application state"
        );
        Ok(())
    }
}

fn col32(row: &rusqlite::Row<'_>, name: &str) -> rusqlite::Result<[u8; 32]> {
    match row.get_ref(name)? {
        rusqlite::types::ValueRef::Blob(bytes) => {
            bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
        }
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn col64(row: &rusqlite::Row<'_>, name: &str) -> rusqlite::Result<u64> {
    match row.get_ref(name)? {
        rusqlite::types::ValueRef::Blob(bytes) => bytes
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| rusqlite::Error::InvalidQuery),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn opt32(row: &rusqlite::Row<'_>, name: &str) -> rusqlite::Result<Option<[u8; 32]>> {
    match row.get_ref(name)? {
        rusqlite::types::ValueRef::Null => Ok(None),
        rusqlite::types::ValueRef::Blob(bytes) => bytes
            .try_into()
            .map(Some)
            .map_err(|_| rusqlite::Error::InvalidQuery),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn opt64(row: &rusqlite::Row<'_>, name: &str) -> rusqlite::Result<Option<u64>> {
    match row.get_ref(name)? {
        rusqlite::types::ValueRef::Null => Ok(None),
        rusqlite::types::ValueRef::Blob(bytes) => bytes
            .try_into()
            .map(|bytes| Some(u64::from_be_bytes(bytes)))
            .map_err(|_| rusqlite::Error::InvalidQuery),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn load_p(connection: &Connection, block: &[u8; 32]) -> Result<Option<StoredEpochPV1>> {
    // Read sizes before blobs; corrupt oversized rows are never copied into an audit.
    let lengths: Option<[i64;9]> = connection.query_row(
        "SELECT length(artifact),length(target_snapshot),length(replay_commands),length(replay_nonces),length(lifecycle),length(header),length(target_set),length(target_parameters),length(edge_lineage) FROM native_durable_execution_p_v1 WHERE block_id=?",
        params![block.as_slice()], |r| Ok([r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?])).optional()?;
    let Some(lengths) = lengths else {
        return Ok(None);
    };
    let caps = [
        trnm_native_application::MAX_NATIVE_EXECUTED_BLOCK_ARTIFACT_BYTES_V0,
        MAX_SNAPSHOT_BYTES,
        MAX_REPLAY_BYTES,
        MAX_REPLAY_BYTES,
        MAX_LIFECYCLE_BYTES,
        MAX_HEADER_BYTES,
        MAX_SET_BYTES,
        MAX_PARAMETERS_BYTES,
        4 + 32 * MAX_EDGES,
    ];
    ensure!(
        lengths
            .iter()
            .zip(caps)
            .all(|(&n, cap)| n >= 0 && n as usize <= cap),
        "epoch P resource budget"
    );
    let value = connection.query_row(
        "SELECT * FROM native_durable_execution_p_v1 WHERE block_id=?",
        params![block.as_slice()],
        |r| {
            let parent = ApplicationHeadV0::new(
                HeightV0::new(col64(r, "parent_height")?),
                BlockIdV0::new(col32(r, "parent_block")?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                StateRootV0::new(col32(r, "parent_root")?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                ApplicationCommitIdV0::new(col32(r, "parent_commit_id")?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
            );
            Ok(StoredEpochPV1 {
                store_id: col32(r, "store_id")?,
                p_sequence: col64(r, "p_sequence")?,
                status: r.get("status")?,
                artifact_kind: r.get("artifact_kind")?,
                artifact: r.get("artifact")?,
                artifact_digest: col32(r, "artifact_digest")?,
                header: r.get("header")?,
                parent_kind: r.get("parent_kind")?,
                parent,
                parent_p_digest: opt32(r, "parent_p_digest")?,
                consensus_parent_height: col64(r, "consensus_parent_height")?,
                consensus_parent_block: col32(r, "consensus_parent_block")?,
                target_height: col64(r, "target_height")?,
                block_id: col32(r, "block_id")?,
                lineage: r.get("edge_lineage")?,
                lineage_digest: col32(r, "lineage_digest")?,
                snapshot: r.get("target_snapshot")?,
                snapshot_digest: col32(r, "snapshot_digest")?,
                commands: r.get("replay_commands")?,
                nonces: r.get("replay_nonces")?,
                lifecycle: r.get("lifecycle")?,
                target_set: r.get("target_set")?,
                target_parameters: r.get("target_parameters")?,
                p_digest: col32(r, "p_digest")?,
                commit_sequence: opt64(r, "commit_sequence")?,
                commit_id: opt32(r, "commit_id")?,
            })
        },
    )?;
    Ok(Some(value))
}

/// Load the unique committed schema-4 P at a target height.  Prepared rows
/// are intentionally ignored: a height-keyed finalized read must never pick a
/// speculative fork.  More than one committed row at a height is treated as
/// corruption rather than resolved by sequence ordering.
fn load_committed_p_by_height(
    connection: &Connection,
    target_height: u64,
) -> Result<Option<StoredEpochPV1>> {
    let mut statement = connection.prepare(
        "SELECT block_id FROM native_durable_execution_p_v1 \
         WHERE target_height=? AND status=1 ORDER BY p_sequence",
    )?;
    let ids = statement
        .query_map(params![target_height.to_be_bytes().as_slice()], |row| {
            col32(row, "block_id")
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        ids.len() <= 1,
        "schema4 finalized read has multiple committed rows at height"
    );
    ids.first()
        .map(|id| load_p(connection, id)?.context("schema4 committed P disappeared"))
        .transpose()
}

struct StoredEdgeV1 {
    binding: [u8; 32],
    checkpoint: ApplicationHeadV0,
    checkpoint_p_digest: [u8; 32],
    checkpoint_sequence: u64,
    terminal_height: u64,
    terminal_block: [u8; 32],
    first_height: u64,
    evidence: EpochRecoveryEvidenceV1,
    phase: i64,
    consumed: Option<[u8; 32]>,
    consumed_sequence: Option<u64>,
}

/// The durable phase of one retained epoch edge.  This is an observation of
/// the on-disk state, never an execution or voting permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochEdgePhaseV1 {
    Installed,
    Consumed,
}

/// One entry in the versioned schema-4 epoch-edge history.  The lineage is
/// ordered from the genesis-era edge through this entry and is re-audited
/// before this carrier is returned.  Keeping the lineage in the carrier makes
/// a recovery caller prove which prior edges it is joining rather than passing
/// an arbitrary binding into the singleton recovery seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochEdgeHistoryEntryV1 {
    binding: [u8; 32],
    checkpoint: ApplicationHeadV0,
    checkpoint_sequence: u64,
    terminal_height: u64,
    terminal_block: [u8; 32],
    first_height: u64,
    phase: EpochEdgePhaseV1,
    consumed_block: Option<[u8; 32]>,
    consumed_sequence: Option<u64>,
    lineage: Vec<[u8; 32]>,
}

impl EpochEdgeHistoryEntryV1 {
    pub const fn binding(&self) -> [u8; 32] {
        self.binding
    }
    pub const fn checkpoint(&self) -> &ApplicationHeadV0 {
        &self.checkpoint
    }
    pub const fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }
    pub const fn terminal_height(&self) -> u64 {
        self.terminal_height
    }
    pub const fn terminal_block(&self) -> [u8; 32] {
        self.terminal_block
    }
    pub const fn first_height(&self) -> u64 {
        self.first_height
    }
    pub const fn phase(&self) -> EpochEdgePhaseV1 {
        self.phase
    }
    pub const fn consumed_block(&self) -> Option<[u8; 32]> {
        self.consumed_block
    }
    pub const fn consumed_sequence(&self) -> Option<u64> {
        self.consumed_sequence
    }
    pub fn lineage(&self) -> &[[u8; 32]] {
        &self.lineage
    }
}

/// Owner-affine, versioned read of all retained epoch edges.  It is the first
/// multi-edge recovery contract: every row, phase transition, and recursive
/// lineage is checked together.  It intentionally does not authorize a
/// second edge, and an unconsumed edge after the first one is rejected until
/// the dedicated two-seal/handoff bridge exists.
#[must_use = "the epoch-edge history must remain joined to its owner"]
pub struct EpochEdgeHistoryV1 {
    owner: Arc<()>,
    application_head: ApplicationHeadV0,
    entries: Vec<EpochEdgeHistoryEntryV1>,
}

/// Authenticated context for the *next* epoch checkpoint.
///
/// This is an observation carrier, not a checkpoint or signing capability.
/// It is deliberately exposed before the later checkpoint bridge is
/// implemented so callers can bind their planning state to the exact
/// committed epoch context instead of retrying the legacy epoch-0 APIs.  The
/// carrier is owner-affine and is rebuilt from the singleton context row and
/// recursively audited edge history on every request.
#[must_use = "later-epoch context must remain joined to its durable owner"]
pub struct LaterEpochCheckpointContextV1 {
    owner: Arc<()>,
    application_head: ApplicationHeadV0,
    predecessor_edge: [u8; 32],
    lineage: Vec<[u8; 32]>,
    old_validator_set: ValidatorSet,
    old_parameters: ConsensusParametersV0,
    epoch: trnm_consensus_types::Epoch,
    checkpoint_height: trnm_consensus_types::Height,
    seal_1_height: trnm_consensus_types::Height,
    seal_2_height: trnm_consensus_types::Height,
    first_application_height: trnm_consensus_types::Height,
    cutoff_height: trnm_consensus_types::Height,
    context_digest: [u8; 32],
}

/// The exact successor-edge facts that must be persisted after a later
/// checkpoint/finality commit.  This is an observation carrier only: it has
/// no execution, signing, or activation authority.  Keeping these facts
/// explicit prevents callers from accidentally treating the schema-8
/// checkpoint-finality row as the second application edge.
#[must_use = "later-edge requirements must remain joined to their owner"]
pub struct LaterEpochApplicationEdgeRequirementsV1 {
    owner: Arc<()>,
    predecessor_edge: [u8; 32],
    successor_binding: [u8; 32],
    checkpoint_block: [u8; 32],
    checkpoint_height: u64,
    terminal_height: u64,
    terminal_block: [u8; 32],
    first_application_height: u64,
    checkpoint_commit_sequence: u64,
    proof_context_digest: [u8; 32],
    successor_context_digest: [u8; 32],
}

/// Owner-affine durable successor edge installed by a committed later-epoch
/// checkpoint. This capability is intentionally narrower than the legacy
/// `AuthenticatedEpochApplicationEdgeV1`: it proves that the successor edge
/// is present and unchanged. The request/header-based C+3 preparation method
/// performs candidate execution; the legacy edge-only method remains
/// fail-closed because it has no block inputs.
#[must_use = "later successor edge must remain joined to its durable owner"]
pub struct LaterEpochApplicationEdgeV1 {
    owner: Arc<()>,
    successor_binding: [u8; 32],
    predecessor_edge: [u8; 32],
    checkpoint_block: [u8; 32],
    checkpoint_p_digest: [u8; 32],
    checkpoint_commit_sequence: u64,
    checkpoint_height: u64,
    checkpoint_root: [u8; 32],
    checkpoint_commit_id: [u8; 32],
    terminal_height: u64,
    terminal_block: [u8; 32],
    first_height: u64,
    proof_context_digest: [u8; 32],
    successor_context_digest: [u8; 32],
    authority_digest: [u8; 32],
    record_digest: [u8; 32],
}

impl LaterEpochApplicationEdgeV1 {
    pub const fn successor_binding(&self) -> [u8; 32] {
        self.successor_binding
    }
    pub const fn predecessor_edge(&self) -> [u8; 32] {
        self.predecessor_edge
    }
    pub const fn checkpoint_block(&self) -> [u8; 32] {
        self.checkpoint_block
    }
    pub const fn checkpoint_p_digest(&self) -> [u8; 32] {
        self.checkpoint_p_digest
    }
    pub const fn checkpoint_commit_sequence(&self) -> u64 {
        self.checkpoint_commit_sequence
    }
    pub const fn checkpoint_height(&self) -> u64 {
        self.checkpoint_height
    }
    pub const fn checkpoint_root(&self) -> [u8; 32] {
        self.checkpoint_root
    }
    pub const fn checkpoint_commit_id(&self) -> [u8; 32] {
        self.checkpoint_commit_id
    }
    pub const fn terminal_height(&self) -> u64 {
        self.terminal_height
    }
    pub const fn terminal_block(&self) -> [u8; 32] {
        self.terminal_block
    }
    pub const fn first_application_height(&self) -> u64 {
        self.first_height
    }
    pub const fn proof_context_digest(&self) -> [u8; 32] {
        self.proof_context_digest
    }
    pub const fn successor_context_digest(&self) -> [u8; 32] {
        self.successor_context_digest
    }
    pub const fn authority_digest(&self) -> [u8; 32] {
        self.authority_digest
    }
    pub const fn record_digest(&self) -> [u8; 32] {
        self.record_digest
    }
    pub fn belongs_to_application(&self, application: &DurableNativeApplicationV0) -> bool {
        Arc::ptr_eq(&self.owner, &application.owner_affinity)
    }

    /// Crate-internal transition coordinates for a future incremental/JMT
    /// adapter.  This is deliberately separate from
    /// `AuthenticatedEpochApplicationEdgeV1`; callers still need to load and
    /// verify the retained old/new configuration before constructing the
    /// complete PoCO rollover context.
    #[allow(dead_code)]
    pub(crate) fn coordinates_v1(&self) -> crate::epoch_edge::EpochApplicationCoordinatesV1 {
        crate::epoch_edge::EpochApplicationCoordinatesV1 {
            checkpoint_version: self.checkpoint_height,
            checkpoint_root: self.checkpoint_root,
            terminal_version: self.terminal_height,
            first_version: self.first_height,
            authorization_id: self.successor_binding,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn application_parent_v1(&self) -> ApplicationHeadV0 {
        ApplicationHeadV0::new(
            HeightV0::new(self.checkpoint_height),
            BlockIdV0::new(self.checkpoint_block).expect("validated checkpoint block"),
            StateRootV0::new(self.checkpoint_root).expect("validated checkpoint root"),
            ApplicationCommitIdV0::new(self.checkpoint_commit_id).expect("validated commit id"),
        )
    }
}

/// Strict, owner-created transition context for a later successor edge.  The
/// public edge intentionally retains only compact ledger facts; this carrier
/// owns the decoded old/new configuration and terminal header needed by the
/// execution engines.  It is created only after re-auditing the retained
/// schema-8 proof and the committed checkpoint P row.
pub(crate) struct LaterEpochExecutionContextV1 {
    application_parent: ApplicationHeadV0,
    consensus_parent: BlockHeader,
    old_validator_set: ValidatorSet,
    old_parameters: ConsensusParametersV0,
    new_validator_set: ValidatorSet,
    new_parameters: ConsensusParametersV0,
    coordinates: crate::epoch_edge::EpochApplicationCoordinatesV1,
    authorization_id: [u8; 32],
}

impl crate::epoch_edge::sealed::Sealed for LaterEpochExecutionContextV1 {}

impl crate::epoch_edge::EpochExecutionContextV1 for LaterEpochExecutionContextV1 {
    fn application_parent_v1(&self) -> &ApplicationHeadV0 {
        &self.application_parent
    }
    fn consensus_parent_v1(&self) -> &BlockHeader {
        &self.consensus_parent
    }
    fn first_application_height_v1(&self) -> u64 {
        self.coordinates.first_version
    }
    fn old_validator_set_v1(&self) -> &ValidatorSet {
        &self.old_validator_set
    }
    fn old_parameters_v1(&self) -> &ConsensusParametersV0 {
        &self.old_parameters
    }
    fn new_validator_set_v1(&self) -> &ValidatorSet {
        &self.new_validator_set
    }
    fn new_parameters_v1(&self) -> &ConsensusParametersV0 {
        &self.new_parameters
    }
    fn authorization_id_v1(&self) -> [u8; 32] {
        self.authorization_id
    }
    fn coordinates_v1(&self) -> crate::epoch_edge::EpochApplicationCoordinatesV1 {
        self.coordinates
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LaterSuccessorFactsV1 {
    successor_binding: [u8; 32],
    predecessor_edge: [u8; 32],
    checkpoint_block: [u8; 32],
    checkpoint_p_digest: [u8; 32],
    checkpoint_commit_sequence: u64,
    checkpoint_height: u64,
    checkpoint_root: [u8; 32],
    checkpoint_commit_id: [u8; 32],
    terminal_height: u64,
    terminal_block: [u8; 32],
    first_height: u64,
    proof_context_digest: [u8; 32],
    successor_context_digest: [u8; 32],
    authority_digest: [u8; 32],
    record_digest: [u8; 32],
}

impl LaterEpochApplicationEdgeRequirementsV1 {
    pub const fn predecessor_edge(&self) -> [u8; 32] {
        self.predecessor_edge
    }

    pub const fn successor_binding(&self) -> [u8; 32] {
        self.successor_binding
    }

    pub const fn checkpoint_block(&self) -> [u8; 32] {
        self.checkpoint_block
    }

    pub const fn checkpoint_height(&self) -> u64 {
        self.checkpoint_height
    }

    pub const fn terminal_height(&self) -> u64 {
        self.terminal_height
    }

    pub const fn terminal_block(&self) -> [u8; 32] {
        self.terminal_block
    }

    pub const fn first_application_height(&self) -> u64 {
        self.first_application_height
    }

    pub const fn checkpoint_commit_sequence(&self) -> u64 {
        self.checkpoint_commit_sequence
    }

    pub const fn proof_context_digest(&self) -> [u8; 32] {
        self.proof_context_digest
    }

    /// Digest of the post-checkpoint singleton context that a future
    /// successor-edge row must bind.  This is deliberately distinct from the
    /// pre-C18 context digest retained in the schema-8 proof row.
    pub const fn successor_context_digest(&self) -> [u8; 32] {
        self.successor_context_digest
    }

    pub fn belongs_to_application(&self, application: &DurableNativeApplicationV0) -> bool {
        Arc::ptr_eq(&self.owner, &application.owner_affinity)
    }
}

impl LaterEpochCheckpointContextV1 {
    pub fn application_head(&self) -> &ApplicationHeadV0 {
        &self.application_head
    }

    pub const fn predecessor_edge(&self) -> [u8; 32] {
        self.predecessor_edge
    }

    pub fn lineage(&self) -> &[[u8; 32]] {
        &self.lineage
    }

    pub fn old_validator_set(&self) -> &ValidatorSet {
        &self.old_validator_set
    }

    pub const fn old_parameters(&self) -> &ConsensusParametersV0 {
        &self.old_parameters
    }

    pub const fn epoch(&self) -> trnm_consensus_types::Epoch {
        self.epoch
    }

    pub const fn checkpoint_height(&self) -> trnm_consensus_types::Height {
        self.checkpoint_height
    }

    pub const fn seal_1_height(&self) -> trnm_consensus_types::Height {
        self.seal_1_height
    }

    pub const fn seal_2_height(&self) -> trnm_consensus_types::Height {
        self.seal_2_height
    }

    pub const fn first_application_height(&self) -> trnm_consensus_types::Height {
        self.first_application_height
    }

    pub const fn cutoff_height(&self) -> trnm_consensus_types::Height {
        self.cutoff_height
    }

    pub const fn context_digest(&self) -> [u8; 32] {
        self.context_digest
    }

    pub fn belongs_to_application(&self, application: &DurableNativeApplicationV0) -> bool {
        Arc::ptr_eq(&self.owner, &application.owner_affinity)
    }
}

impl EpochEdgeHistoryV1 {
    pub const fn application_head(&self) -> &ApplicationHeadV0 {
        &self.application_head
    }
    pub fn entries(&self) -> &[EpochEdgeHistoryEntryV1] {
        &self.entries
    }
    pub fn belongs_to_application_at_path_v1(
        &self,
        application: &DurableNativeApplicationV0,
        expected_path: &Path,
    ) -> bool {
        if !Arc::ptr_eq(&self.owner, &application.owner_affinity)
            || application.path() != expected_path
        {
            return false;
        }
        application.read_epoch_edge_history_v1().is_ok_and(|fresh| {
            fresh.application_head == self.application_head && fresh.entries == self.entries
        })
    }
}

fn load_edges(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
) -> Result<Vec<StoredEdgeV1>> {
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM native_epoch_edge_v1", [], |r| {
            r.get(0)
        })?;
    ensure!(
        count >= 0 && count as usize <= MAX_EDGES,
        "epoch edge count budget"
    );
    let bytes: i64 = connection.query_row(
        "SELECT COALESCE(MAX(length(evidence)),0) FROM native_epoch_edge_v1",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        bytes >= 0 && bytes as usize <= MAX_EPOCH_EVIDENCE_BYTES_V1,
        "epoch evidence byte budget"
    );
    let mut statement =
        connection.prepare("SELECT * FROM native_epoch_edge_v1 ORDER BY first_height ASC")?;
    let rows = statement.query_map([], |r| {
        Ok((
            col32(r, "binding")?,
            col32(r, "store_id")?,
            col64(r, "checkpoint_height")?,
            col32(r, "checkpoint_block")?,
            col32(r, "checkpoint_root")?,
            col32(r, "checkpoint_commit_id")?,
            col32(r, "checkpoint_p_digest")?,
            col64(r, "checkpoint_commit_sequence")?,
            col64(r, "terminal_height")?,
            col32(r, "terminal_block")?,
            col64(r, "first_height")?,
            r.get::<_, Vec<u8>>("evidence")?,
            col32(r, "evidence_digest")?,
            r.get::<_, i64>("phase")?,
            opt32(r, "consumed_block")?,
            opt64(r, "consumed_sequence")?,
        ))
    })?;
    let mut values = Vec::new();
    for row in rows {
        let r = row?;
        ensure!(
            r.1 == config.store_id
                && r.11.len() <= MAX_EPOCH_EVIDENCE_BYTES_V1
                && sha256_v0(&r.11) == r.12,
            "epoch edge source/digest"
        );
        values.push(StoredEdgeV1 {
            binding: r.0,
            checkpoint: ApplicationHeadV0::new(
                HeightV0::new(r.2),
                BlockIdV0::new(r.3)?,
                StateRootV0::new(r.4)?,
                ApplicationCommitIdV0::new(r.5)?,
            ),
            checkpoint_p_digest: r.6,
            checkpoint_sequence: r.7,
            terminal_height: r.8,
            terminal_block: r.9,
            first_height: r.10,
            evidence: EpochRecoveryEvidenceV1::decode(&r.11)?,
            phase: r.13,
            consumed: r.14,
            consumed_sequence: r.15,
        });
    }
    Ok(values)
}

fn encode_lineage(ids: &[[u8; 32]]) -> Result<Vec<u8>> {
    ensure!(ids.len() <= MAX_EDGES, "epoch lineage count budget");
    let mut bytes = (ids.len() as u32).to_be_bytes().to_vec();
    for id in ids {
        bytes.extend_from_slice(id);
    }
    Ok(bytes)
}
fn decode_lineage(bytes: &[u8]) -> Result<Vec<[u8; 32]>> {
    ensure!(bytes.len() >= 4, "epoch lineage truncated");
    let count = u32::from_be_bytes(bytes[..4].try_into()?) as usize;
    ensure!(
        count <= MAX_EDGES && bytes.len() == 4 + 32 * count,
        "epoch lineage count/length mismatch"
    );
    let values = bytes[4..]
        .chunks_exact(32)
        .map(|v| v.try_into().expect("exact chunk"))
        .collect::<Vec<_>>();
    ensure!(
        values.iter().collect::<BTreeSet<_>>().len() == count,
        "duplicate lineage edge"
    );
    Ok(values)
}

// The caller has authenticated inventory in this same connection. These
// selected ancestry joins never re-enter inventory or public owner recovery.
fn validate_prefix_current_ancestry_v1(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    head: &ApplicationHeadV0,
    prefix: &lineage_resolver::Prefix,
) -> Result<()> {
    validate_prefix_current_ancestry_with_read_policy(
        connection,
        config,
        head,
        prefix,
        EpochReadPolicyV1::Physical,
    )
}

fn validate_prefix_current_ancestry_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    head: &ApplicationHeadV0,
    prefix: &lineage_resolver::Prefix,
    policy: EpochReadPolicyV1<'_>,
) -> Result<()> {
    if let Some(entry) = prefix
        .entries
        .iter()
        .rev()
        .find(|entry| entry.later_facts.is_some() && entry.phase == 1)
    {
        let consumed = load_p(
            connection,
            &entry.consumed.context("later consumed block missing")?,
        )?
        .context("later consumed application P missing")?;
        validate_consumed_later_ancestry_with_read_policy(
            connection, config, head, &consumed, policy,
        )?;
    }
    Ok(())
}

#[inline(never)]
fn validate_consumed_later_ancestry_v1(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    head: &ApplicationHeadV0,
    consumed: &StoredEpochPV1,
) -> Result<()> {
    validate_consumed_later_ancestry_with_read_policy(
        connection,
        config,
        head,
        consumed,
        EpochReadPolicyV1::Physical,
    )
}

fn validate_consumed_later_ancestry_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    head: &ApplicationHeadV0,
    consumed: &StoredEpochPV1,
    policy: EpochReadPolicyV1<'_>,
) -> Result<()> {
    ensure!(
        consumed.status == 1 && consumed.artifact_kind == 1,
        "later consumed application P phase/kind"
    );
    let consumed_head = consumed.target_head()?;
    if head == &consumed_head {
        return Ok(());
    }
    let current = load_p(connection, head.block_id().as_bytes())?
        .context("later consumed descendant P missing")?;
    let history = lineage_resolver::resolve_with_read_policy(
        connection,
        config,
        &decode_lineage(&current.lineage)?,
        policy,
    )?;
    let original = decode_lineage(&consumed.lineage)?;
    let mut visited = BTreeSet::new();
    let mut cursor = head.clone();
    for _ in 0..MAX_P_ROWS {
        if cursor == consumed_head {
            return Ok(());
        }
        ensure!(
            visited.insert(*cursor.block_id().as_bytes()),
            "later consumed ancestry cycle"
        );
        let row = load_p(connection, cursor.block_id().as_bytes())?
            .context("later consumed descendant P missing")?;
        let lineage = decode_lineage(&row.lineage)?;
        ensure!(
            row.status == 1
                && row.parent_kind == 1
                && row.target_head()? == cursor
                && lineage.starts_with(&original)
                && row.target_height > consumed.target_height,
            "later consumed descendant context mismatch"
        );
        let parent = load_p(connection, row.parent.block_id().as_bytes())?
            .context("later consumed descendant parent missing")?;
        ensure!(
            parent.status == 1
                && parent.target_head()? == row.parent
                && row.parent_p_digest == Some(parent.p_digest)
                && parent
                    .commit_sequence
                    .zip(row.commit_sequence)
                    .is_some_and(|(a, b)| a < b),
            "later consumed descendant parent mismatch"
        );
        if row.artifact_kind == 0 {
            ensure!(
                row.lineage == parent.lineage
                    && row.target_set == parent.target_set
                    && row.target_parameters == parent.target_parameters
                    && parent.target_height.checked_add(1) == Some(row.target_height)
                    && row.consensus_parent_height == parent.target_height
                    && row.consensus_parent_block == parent.block_id,
                "later consumed ordinary parent mismatch"
            );
        } else {
            ensure!(
                row.artifact_kind == 1,
                "later consumed descendant artifact kind"
            );
            let binding = lineage
                .last()
                .context("later consumed handoff lineage missing")?;
            let edge = history
                .entries
                .iter()
                .find(|entry| entry.binding == *binding)
                .context("later consumed handoff edge missing")?;
            let coordinates = edge.audit.coordinates(*binding)?;
            let activation = &edge.audit.activation;
            let terminal = activation.old_checkpoint_finality().grandchild().header();
            let mut expected_lineage = decode_lineage(&parent.lineage)?;
            expected_lineage.push(*binding);
            ensure!(
                edge.later_facts.is_some()
                    && edge.phase == 1
                    && edge.consumed == Some(row.block_id)
                    && edge.consumed_sequence == row.commit_sequence
                    && edge.checkpoint == row.parent
                    && edge.checkpoint_p_digest == parent.p_digest
                    && parent.commit_sequence == Some(edge.checkpoint_sequence)
                    && lineage == expected_lineage
                    && parent.target_height.checked_add(3) == Some(row.target_height)
                    && parent.target_height == coordinates.checkpoint_version
                    && row.target_height == coordinates.first_version
                    && row.consensus_parent_height == coordinates.terminal_version
                    && row.consensus_parent_block == *terminal.id().as_bytes()
                    && parent.target_set
                        == activation
                            .old_validator_set()
                            .try_cev0_bytes()
                            .map_err(|e| anyhow::anyhow!("ancestry old set: {e:?}"))?
                    && parent.target_parameters
                        == activation.old_consensus_parameters().canonical_bytes()
                    && row.target_set
                        == activation
                            .new_validator_set()
                            .try_cev0_bytes()
                            .map_err(|e| anyhow::anyhow!("ancestry new set: {e:?}"))?
                    && row.target_parameters
                        == activation.new_consensus_parameters().canonical_bytes(),
                "later consumed handoff binding mismatch"
            );
            ensure!(
                has_later_application_finality_schema(policy.schema(connection)?),
                "later consumed handoff proof ledger missing"
            );
            let proof = connection.query_row(
                "SELECT p_digest,commit_sequence,edge_binding,proof_digest,record_digest
                 FROM native_later_epoch_application_finality_v1 WHERE block_id=?1",
                [row.block_id.as_slice()],
                |r| {
                    Ok((
                        col32(r, "p_digest")?,
                        col64(r, "commit_sequence")?,
                        col32(r, "edge_binding")?,
                        col32(r, "proof_digest")?,
                        col32(r, "record_digest")?,
                    ))
                },
            )?;
            ensure!(
                proof.0 == row.p_digest
                    && Some(proof.1) == row.commit_sequence
                    && proof.2 == *binding
                    && proof.4
                        == later_application_finality_record_digest(
                            config,
                            &row.block_id,
                            &row.p_digest,
                            proof.1,
                            binding,
                            &proof.3
                        ),
                "later consumed handoff proof binding mismatch"
            );
        }
        cursor = row.parent;
    }
    anyhow::bail!("later consumed descendant ancestry budget")
}

fn later_table_installed(connection: &Connection) -> Result<bool> {
    Ok(later_finality_table_installed(connection)?
        && later_edge_table_installed(connection)?
        && later_edge_has_commit_id_column(connection)?)
}

fn later_application_finality_table_installed(connection: &Connection) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='native_later_epoch_application_finality_v1')",
        [],
        |row| row.get(0),
    )?)
}

fn later_finality_table_installed(connection: &Connection) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='native_later_epoch_finality_v1')",
        [],
        |row| row.get(0),
    )?)
}

fn later_edge_table_installed(connection: &Connection) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='native_later_epoch_edge_v1')",
        [],
        |row| row.get(0),
    )?)
}

fn later_edge_has_commit_id_column(connection: &Connection) -> Result<bool> {
    if !later_edge_table_installed(connection)? {
        return Ok(false);
    }
    let mut statement = connection.prepare("PRAGMA table_info(native_later_epoch_edge_v1)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns
        .iter()
        .any(|column| column == "checkpoint_commit_id"))
}

fn later_record_digest(
    config: &NativeApplicationConfigV0,
    checkpoint_block: &[u8; 32],
    p_digest: &[u8; 32],
    sequence: u64,
    preimages: &crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1,
) -> [u8; 32] {
    hash_domain(
        "trnm.native-application.later-epoch-finality-record.v1",
        &[
            &config.store_id,
            checkpoint_block,
            p_digest,
            &sequence.to_be_bytes(),
            &preimages.context_digest,
            &preimages.predecessor_edge,
            &sha256_v0(&preimages.checkpoint_parent_header),
            &sha256_v0(&preimages.checkpoint_header),
            &sha256_v0(&preimages.checkpoint_finality),
            &sha256_v0(&preimages.anchor_kernel),
            &sha256_v0(&preimages.next_epoch_commitment),
            &sha256_v0(&preimages.new_validator_set),
            &sha256_v0(&preimages.new_parameters),
        ],
    )
}

fn later_application_finality_record_digest(
    config: &NativeApplicationConfigV0,
    block_id: &[u8; 32],
    p_digest: &[u8; 32],
    sequence: u64,
    edge_binding: &[u8; 32],
    proof_digest: &[u8; 32],
) -> [u8; 32] {
    hash_domain(
        "trnm.native-application.later-epoch-application-finality.v1",
        &[
            &config.store_id,
            block_id,
            p_digest,
            &sequence.to_be_bytes(),
            edge_binding,
            proof_digest,
        ],
    )
}

fn validate_later_application_finality_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    policy: EpochReadPolicyV1<'_>,
) -> Result<()> {
    let version = policy.schema(connection)?;
    if !has_later_application_finality_schema(version) {
        return Ok(());
    }
    ensure!(
        later_application_finality_table_installed(connection)?,
        "later application finality ledger missing"
    );
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_later_epoch_application_finality_v1",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        count >= 0 && count as usize <= MAX_EDGES,
        "later application finality count budget"
    );
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_later_epoch_application_finality_v1 WHERE
         typeof(proof)!='blob' OR length(proof) NOT BETWEEN 1 AND 67108864",
        [],
        |row| row.get(0),
    )?;
    ensure!(invalid == 0, "later application finality proof bounds");
    let consumed_edges: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_later_epoch_edge_v1 WHERE phase=1",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        count == consumed_edges,
        "later application finality ledger must cover every consumed successor"
    );
    let missing: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_later_epoch_edge_v1 e
         WHERE e.phase=1 AND NOT EXISTS (
           SELECT 1 FROM native_later_epoch_application_finality_v1 f
           WHERE f.edge_binding=e.successor_binding
         )",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        missing == 0,
        "consumed successor application finality missing"
    );
    let mut statement = connection.prepare(
        "SELECT block_id,p_digest,commit_sequence,edge_binding,proof,proof_digest,record_digest
         FROM native_later_epoch_application_finality_v1 ORDER BY commit_sequence",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            col32(row, "block_id")?,
            col32(row, "p_digest")?,
            col64(row, "commit_sequence")?,
            col32(row, "edge_binding")?,
            row.get::<_, Vec<u8>>("proof")?,
            col32(row, "proof_digest")?,
            col32(row, "record_digest")?,
        ))
    })?;
    let mut previous_sequence = 0;
    for row in rows {
        let (block_id, p_digest, sequence, edge_binding, proof, proof_digest, record_digest) = row?;
        ensure!(
            sequence > previous_sequence,
            "later application finality sequence order"
        );
        previous_sequence = sequence;
        ensure!(
            sha256_v0(&proof) == proof_digest,
            "later application proof digest"
        );
        ensure!(
            record_digest
                == later_application_finality_record_digest(
                    config,
                    &block_id,
                    &p_digest,
                    sequence,
                    &edge_binding,
                    &proof_digest,
                ),
            "later application finality record digest"
        );
        let p = load_p(connection, &block_id)?.context("later application finality P missing")?;
        ensure!(
            p.status == 1
                && p.artifact_kind == 1
                && p.p_digest == p_digest
                && p.commit_sequence == Some(sequence)
                && decode_lineage(&p.lineage)?.last() == Some(&edge_binding),
            "later application finality P binding"
        );
        let (phase, consumed_block, consumed_sequence): (i64, Option<Vec<u8>>, Option<Vec<u8>>) =
            connection.query_row(
                "SELECT phase,consumed_block,consumed_sequence FROM native_later_epoch_edge_v1
                 WHERE successor_binding=?1",
                [edge_binding.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        ensure!(
            phase == 1
                && consumed_block.as_deref() == Some(block_id.as_slice())
                && consumed_sequence
                    .as_deref()
                    .map(|v| v == sequence.to_be_bytes().as_slice())
                    .unwrap_or(false),
            "later application finality edge binding"
        );
        let (predecessor_edge, checkpoint_block): ([u8; 32], [u8; 32]) = connection.query_row(
            "SELECT predecessor_edge,checkpoint_block
                 FROM native_later_epoch_edge_v1 WHERE successor_binding=?1",
            [edge_binding.as_slice()],
            |row| {
                Ok((
                    col32(row, "predecessor_edge")?,
                    col32(row, "checkpoint_block")?,
                ))
            },
        )?;
        validate_later_application_finality_proof_v1_with_read_policy(
            connection,
            config,
            &p,
            &proof,
            edge_binding,
            predecessor_edge,
            checkpoint_block,
            policy,
        )?;
    }
    Ok(())
}

/// Consume only a freshly reconstructed strict activation from the retained
/// prefix. The runtime verifies every original proof signature and authorized
/// anchor, and this boundary preserves the complete caller target expectation.
fn verify_retained_epoch_runtime_finality_v1(
    activation: trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0,
    proof: &[u8],
    expected: trnm_consensus_crypto::FinalityExpectationV0,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<BlockHeader> {
    let runtime =
        trnm_consensus_crypto::StrictEpochRuntimeContextV1::from_activation_v1(activation)
            .map_err(|e| anyhow::anyhow!("retained epoch runtime: {e:?}"))?;
    let verified = runtime
        .decode_verify_finality_v1(proof, expected.parent_timestamp_ms, budget)
        .map_err(|e| anyhow::anyhow!("retained epoch strict finality: {e:?}"))?;
    let header = verified.finalized_block().header();
    if header.block_kind() == BlockKind::EpochHandoff {
        let terminal = runtime.activation().terminal_old_header();
        ensure!(
            expected.parent_id == terminal.id()
                && expected.parent_height == terminal.height()
                && expected.parent_timestamp_ms == terminal.timestamp_ms(),
            "retained epoch first proof expected terminal mismatch"
        );
    }
    ensure!(
        header.id() == expected.block_id
            && header.height() == expected.height
            && header.state_root() == expected.state_root
            && header.receipts_root() == expected.receipts_root
            && header.evidence_root() == expected.evidence_root
            && header.parent_id() == expected.parent_id
            && expected.parent_height.get().checked_add(1) == Some(header.height().get()),
        "retained epoch finality expected target mismatch"
    );
    Ok(header.clone())
}

// The proof identity tuple is intentionally explicit: each field binds a
// distinct retained edge/checkpoint relation, and collapsing it would weaken
// the policy-aware revalidation boundary.
#[allow(clippy::too_many_arguments)]
fn validate_later_application_finality_proof_v1_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    proof: &[u8],
    edge_binding: [u8; 32],
    predecessor_edge: [u8; 32],
    checkpoint_block: [u8; 32],
    policy: EpochReadPolicyV1<'_>,
) -> Result<()> {
    let activation = audit_later_successor_for_lineage_with_read_policy(
        connection,
        config,
        edge_binding,
        predecessor_edge,
        policy,
    )?;
    ensure!(
        activation
            .activation
            .old_checkpoint_finality()
            .finalized_block()
            .header()
            .id()
            .as_bytes()
            == &checkpoint_block,
        "later application checkpoint binding"
    );
    let header = decode_header(&p.header)?;
    let expected = trnm_consensus_crypto::FinalityExpectationV0 {
        block_id: header.id(),
        height: header.height(),
        state_root: header.state_root(),
        receipts_root: header.receipts_root(),
        evidence_root: header.evidence_root(),
        parent_id: trnm_consensus_types::BlockId::new(p.consensus_parent_block),
        parent_height: trnm_consensus_types::Height::new(p.consensus_parent_height),
        parent_timestamp_ms: activation
            .activation
            .old_checkpoint_finality()
            .grandchild()
            .header()
            .timestamp_ms(),
    };
    let verified = verify_retained_epoch_runtime_finality_v1(
        activation.activation,
        proof,
        expected,
        &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
    )?;
    ensure!(verified == header, "later application proof header binding");
    Ok(())
}

fn validate_later_records_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    policy: EpochReadPolicyV1<'_>,
) -> Result<()> {
    let version = policy.schema(connection)?;
    if !has_later_schema(version) {
        return Ok(());
    }
    ensure!(
        later_table_installed(connection)?,
        "later finality table missing"
    );
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_later_epoch_finality_v1",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        count >= 0 && count as usize <= MAX_EDGES,
        "later finality count budget"
    );
    // Bound storage before allocating blobs, including a total record budget.
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_later_epoch_finality_v1 WHERE
         typeof(checkpoint_parent_header)!='blob' OR length(checkpoint_parent_header) NOT BETWEEN 1 AND 4096 OR
         typeof(checkpoint_header)!='blob' OR length(checkpoint_header) NOT BETWEEN 1 AND 4096 OR
         typeof(checkpoint_finality)!='blob' OR length(checkpoint_finality) NOT BETWEEN 1 AND 67108864 OR
         typeof(anchor_kernel)!='blob' OR length(anchor_kernel) NOT BETWEEN 1 AND 67108864 OR
         typeof(next_epoch_commitment)!='blob' OR length(next_epoch_commitment) NOT BETWEEN 1 AND 4096 OR
         typeof(new_validator_set)!='blob' OR length(new_validator_set) NOT BETWEEN 1 AND 1048576 OR
         typeof(new_parameters)!='blob' OR length(new_parameters) NOT BETWEEN 1 AND 4096 OR
         length(checkpoint_parent_header)+length(checkpoint_header)+length(checkpoint_finality)+length(anchor_kernel)+length(next_epoch_commitment)+length(new_validator_set)+length(new_parameters)>67108864",
        [], |row| row.get(0),
    )?;
    ensure!(invalid == 0, "later finality byte/type budget");
    let duplicate_predecessors: i64 = connection.query_row(
        "SELECT COUNT(*) FROM (
             SELECT predecessor_edge FROM native_later_epoch_finality_v1
             GROUP BY predecessor_edge HAVING COUNT(*) > 1
         )",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        duplicate_predecessors == 0,
        "later finality predecessor has multiple successors"
    );
    let mut query = connection.prepare(
        "SELECT checkpoint_block,p_digest,commit_sequence,context_digest,predecessor_edge,
                checkpoint_parent_header,checkpoint_header,checkpoint_finality,anchor_kernel,
                next_epoch_commitment,new_validator_set,new_parameters,record_digest
         FROM native_later_epoch_finality_v1 ORDER BY commit_sequence",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            col32(row, "checkpoint_block")?,
            col32(row, "p_digest")?,
            col64(row, "commit_sequence")?,
            col32(row, "context_digest")?,
            col32(row, "predecessor_edge")?,
            row.get::<_, Vec<u8>>("checkpoint_parent_header")?,
            row.get::<_, Vec<u8>>("checkpoint_header")?,
            row.get::<_, Vec<u8>>("checkpoint_finality")?,
            row.get::<_, Vec<u8>>("anchor_kernel")?,
            row.get::<_, Vec<u8>>("next_epoch_commitment")?,
            row.get::<_, Vec<u8>>("new_validator_set")?,
            row.get::<_, Vec<u8>>("new_parameters")?,
            col32(row, "record_digest")?,
        ))
    })?;
    let mut previous_sequence = 0;
    for row in rows {
        let (
            checkpoint_block,
            p_digest,
            sequence,
            context_digest,
            predecessor_edge,
            checkpoint_parent_header,
            checkpoint_header,
            checkpoint_finality,
            anchor_kernel,
            next_epoch_commitment,
            new_validator_set,
            new_parameters,
            record_digest,
        ) = row?;
        ensure!(
            sequence > previous_sequence,
            "later finality sequence order"
        );
        previous_sequence = sequence;
        ensure!(
            !checkpoint_parent_header.is_empty()
                && checkpoint_parent_header.len() <= MAX_HEADER_BYTES,
            "later parent header bounds"
        );
        ensure!(
            !checkpoint_header.is_empty() && checkpoint_header.len() <= MAX_HEADER_BYTES,
            "later header bounds"
        );
        ensure!(
            checkpoint_finality.len() <= MAX_EPOCH_EVIDENCE_BYTES_V1,
            "later finality bounds"
        );
        ensure!(
            anchor_kernel.len() <= MAX_EPOCH_EVIDENCE_BYTES_V1,
            "later anchor bounds"
        );
        ensure!(
            next_epoch_commitment.len() <= MAX_HEADER_BYTES,
            "later commitment bounds"
        );
        ensure!(
            new_validator_set.len() <= MAX_SET_BYTES,
            "later validator set bounds"
        );
        ensure!(
            new_parameters.len() <= MAX_PARAMETERS_BYTES,
            "later parameter bounds"
        );
        let preimages = crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1 {
            context_digest,
            predecessor_edge,
            checkpoint_parent_header,
            checkpoint_header,
            checkpoint_finality,
            anchor_kernel,
            next_epoch_commitment,
            new_validator_set,
            new_parameters,
        };
        ensure!(
            record_digest
                == later_record_digest(config, &checkpoint_block, &p_digest, sequence, &preimages),
            "later finality record digest"
        );
        let p = load_p(connection, &checkpoint_block)?.context("later finality P missing")?;
        ensure!(
            p.status == 1 && p.p_digest == p_digest && p.commit_sequence == Some(sequence),
            "later finality committed P binding"
        );
        ensure!(p.artifact_kind == 0, "later finality artifact kind");
        let header = decode_header(&p.header)?;
        ensure!(
            header.block_kind() == BlockKind::EpochCheckpoint,
            "later finality checkpoint kind"
        );
        ensure!(
            header
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("later header encode: {e:?}"))?
                == preimages.checkpoint_header,
            "later finality header binding"
        );
        validate_later_preimages_with_read_policy(connection, config, &p, &preimages, policy)?;
    }
    Ok(())
}

fn validate_later_edges_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    policy: EpochReadPolicyV1<'_>,
) -> Result<()> {
    let version = policy.schema(connection)?;
    if !has_later_schema(version) {
        return Ok(());
    }
    ensure!(
        later_finality_table_installed(connection)?,
        "later finality table missing"
    );
    ensure!(
        later_edge_table_installed(connection)?,
        "later successor edge table missing"
    );
    ensure!(
        later_edge_has_commit_id_column(connection)?,
        "later successor edge schema is legacy; explicit migration/rebuild required"
    );
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_later_epoch_edge_v1",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        count >= 0 && count as usize <= MAX_EDGES,
        "later edge count budget"
    );
    let mut statement = connection.prepare(
        "SELECT successor_binding,predecessor_edge,checkpoint_block,checkpoint_p_digest,
                checkpoint_commit_sequence,checkpoint_height,checkpoint_root,checkpoint_commit_id,terminal_height,
                terminal_block,first_height,proof_context_digest,successor_context_digest,
                authority_digest,phase,consumed_block,consumed_sequence,record_digest
         FROM native_later_epoch_edge_v1 ORDER BY checkpoint_commit_sequence",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            col32(row, "successor_binding")?,
            col32(row, "predecessor_edge")?,
            col32(row, "checkpoint_block")?,
            col32(row, "checkpoint_p_digest")?,
            col64(row, "checkpoint_commit_sequence")?,
            col64(row, "checkpoint_height")?,
            col32(row, "checkpoint_root")?,
            col32(row, "checkpoint_commit_id")?,
            col64(row, "terminal_height")?,
            col32(row, "terminal_block")?,
            col64(row, "first_height")?,
            col32(row, "proof_context_digest")?,
            col32(row, "successor_context_digest")?,
            col32(row, "authority_digest")?,
            row.get::<_, i64>("phase")?,
            opt32(row, "consumed_block")?,
            opt64(row, "consumed_sequence")?,
            col32(row, "record_digest")?,
        ))
    })?;
    let mut previous_sequence = 0;
    for row in rows {
        let (
            successor_binding,
            predecessor_edge,
            checkpoint_block,
            checkpoint_p_digest,
            sequence,
            checkpoint_height,
            checkpoint_root,
            checkpoint_commit_id,
            terminal_height,
            terminal_block,
            first_height,
            proof_context_digest,
            successor_context_digest,
            authority_digest,
            phase,
            consumed_block,
            consumed_sequence,
            record_digest,
        ) = row?;
        ensure!(sequence > previous_sequence, "later edge sequence order");
        previous_sequence = sequence;
        ensure!(
            (phase == 0 && consumed_block.is_none() && consumed_sequence.is_none())
                || (phase == 1 && consumed_block.is_some() && consumed_sequence.is_some()),
            "later successor edge phase/consumption shape"
        );
        let p = load_p(connection, &checkpoint_block)?.context("later successor P missing")?;
        ensure!(
            p.status == 1
                && p.p_digest == checkpoint_p_digest
                && p.commit_sequence == Some(sequence)
                && p.artifact_kind == 0,
            "later successor P binding"
        );
        if phase == 0 {
            ensure!(
                policy.head(connection, config)? == p.target_head()?,
                "installed later successor requires current checkpoint head"
            );
        } else {
            let consumed = load_p(
                connection,
                &consumed_block.context("later consumed block missing")?,
            )?
            .context("later consumed P missing")?;
            ensure!(
                consumed.status == 1
                    && consumed.artifact_kind == 1
                    && consumed.commit_sequence == consumed_sequence
                    && decode_lineage(&consumed.lineage)?.last() == Some(&successor_binding),
                "later successor consumed P binding"
            );
        }
        let header = decode_header(&p.header)?;
        ensure!(
            header.height().get() == checkpoint_height
                && header.state_root().as_bytes() == &checkpoint_root
                && p.target_head()?.commit_id().as_bytes() == &checkpoint_commit_id,
            "later successor checkpoint geometry"
        );
        let evidence = connection.query_row(
            "SELECT context_digest,predecessor_edge,checkpoint_parent_header,
                    checkpoint_header,checkpoint_finality,anchor_kernel,
                    next_epoch_commitment,new_validator_set,new_parameters
             FROM native_later_epoch_finality_v1 WHERE checkpoint_block=?1",
            [checkpoint_block.as_slice()],
            |row| {
                Ok(
                    crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1 {
                        context_digest: col32(row, "context_digest")?,
                        predecessor_edge: col32(row, "predecessor_edge")?,
                        checkpoint_parent_header: row.get(2)?,
                        checkpoint_header: row.get(3)?,
                        checkpoint_finality: row.get(4)?,
                        anchor_kernel: row.get(5)?,
                        next_epoch_commitment: row.get(6)?,
                        new_validator_set: row.get(7)?,
                        new_parameters: row.get(8)?,
                    },
                )
            },
        )?;
        let facts = derive_later_successor_facts_with_read_policy(
            connection, config, &p, sequence, &evidence, policy,
        )?;
        ensure!(
            facts.successor_binding == successor_binding
                && facts.predecessor_edge == predecessor_edge
                && facts.checkpoint_block == checkpoint_block
                && facts.checkpoint_p_digest == checkpoint_p_digest
                && facts.checkpoint_commit_sequence == sequence
                && facts.checkpoint_height == checkpoint_height
                && facts.checkpoint_root == checkpoint_root
                && facts.checkpoint_commit_id == checkpoint_commit_id
                && facts.terminal_height == terminal_height
                && facts.terminal_block == terminal_block
                && facts.first_height == first_height
                && facts.proof_context_digest == proof_context_digest
                && facts.successor_context_digest == successor_context_digest
                && facts.authority_digest == authority_digest
                && facts.record_digest == record_digest,
            "later successor edge record binding",
        );
    }
    Ok(())
}

/// Strict recovery joins retained evidence to the authenticated local history.
/// It deliberately uses no live context API: after C commits, the current
/// head is C, whereas the observation's context is the retained C-1 commit.
fn validate_later_preimages_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    evidence: &crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1,
    policy: EpochReadPolicyV1<'_>,
) -> Result<()> {
    let prefix = lineage_resolver::resolve_with_read_policy(
        connection,
        config,
        &decode_lineage(&p.lineage)?,
        policy,
    )?;
    lineage_resolver::verify_checkpoint(connection, config, p, evidence, &prefix)?;
    Ok(())
}

/// Reconstruct the successor edge from the exact retained CEV0 preimages.
/// This is intentionally separate from the legacy edge constructor: the
/// predecessor is read from the committed lineage, the binding is returned
/// by strict authority verification, and the post-C18 context is derived from
/// the committed P row.  No caller-provided coordinates enter this function.
fn derive_later_successor_facts(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    sequence: u64,
    evidence: &crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1,
) -> Result<LaterSuccessorFactsV1> {
    derive_later_successor_facts_with_read_policy(
        connection,
        config,
        p,
        sequence,
        evidence,
        EpochReadPolicyV1::Physical,
    )
}

fn derive_later_successor_facts_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    sequence: u64,
    evidence: &crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1,
    policy: EpochReadPolicyV1<'_>,
) -> Result<LaterSuccessorFactsV1> {
    let prefix = lineage_resolver::resolve_with_read_policy(
        connection,
        config,
        &decode_lineage(&p.lineage)?,
        policy,
    )?;
    let audit = lineage_resolver::verify_checkpoint(connection, config, p, evidence, &prefix)?;
    derive_later_successor_facts_from_audit(config, p, sequence, evidence, &audit)
}

fn derive_later_successor_facts_from_audit(
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    sequence: u64,
    evidence: &crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1,
    audit: &crate::epoch_recovery::AuditedEpochEvidenceV1,
) -> Result<LaterSuccessorFactsV1> {
    let predecessor_edge = evidence.predecessor_edge;
    let authority = &audit.activation;
    let old_set = authority.old_validator_set();
    let old_parameters = authority.old_consensus_parameters();
    let header = decode_header(&p.header)?;
    ensure!(
        authority
            .old_checkpoint_finality()
            .finalized_block()
            .header()
            == &header,
        "successor authority checkpoint substitution"
    );
    let geometry = trnm_consensus_types::EpochGeometryV0::new(old_set.epoch(), old_parameters)
        .map_err(|e| anyhow::anyhow!("successor edge geometry: {e:?}"))?;
    let terminal = authority.old_checkpoint_finality().grandchild().header();
    ensure!(
        terminal.height() == geometry.epoch_end(),
        "successor edge terminal geometry"
    );
    let first_height = terminal
        .height()
        .get()
        .checked_add(1)
        .context("successor edge first height exhausted")?;
    let target_head = p.target_head()?;
    let checkpoint_commit_id = *target_head.commit_id().as_bytes();
    let successor_context_digest = context_digest(
        config.store_id,
        &target_head,
        sequence,
        &p.target_set,
        &p.target_parameters,
        &p.lineage,
    );
    let successor_binding = *authority.binding_ref().as_bytes();
    let checkpoint_root = *header.state_root().as_bytes();
    let authority_digest = hash_domain(
        "trnm.native-application.later-epoch-successor-authority.v1",
        &[
            &config.store_id,
            &successor_binding,
            &predecessor_edge,
            &p.block_id,
            &p.p_digest,
            &sha256_v0(&evidence.checkpoint_parent_header),
            &sha256_v0(&evidence.checkpoint_header),
            &sha256_v0(&evidence.checkpoint_finality),
            &sha256_v0(&evidence.anchor_kernel),
            &sha256_v0(&evidence.next_epoch_commitment),
            &sha256_v0(&evidence.new_validator_set),
            &sha256_v0(&evidence.new_parameters),
        ],
    );
    let record_digest = hash_domain(
        "trnm.native-application.later-epoch-successor-record.v1",
        &[
            &config.store_id,
            &successor_binding,
            &predecessor_edge,
            &p.block_id,
            &p.p_digest,
            &sequence.to_be_bytes(),
            &header.height().get().to_be_bytes(),
            &checkpoint_root,
            &checkpoint_commit_id,
            &terminal.height().get().to_be_bytes(),
            terminal.id().as_bytes(),
            &first_height.to_be_bytes(),
            &evidence.context_digest,
            &successor_context_digest,
            &authority_digest,
        ],
    );
    Ok(LaterSuccessorFactsV1 {
        successor_binding,
        predecessor_edge,
        checkpoint_block: p.block_id,
        checkpoint_p_digest: p.p_digest,
        checkpoint_commit_sequence: sequence,
        checkpoint_height: header.height().get(),
        checkpoint_root,
        checkpoint_commit_id,
        terminal_height: terminal.height().get(),
        terminal_block: *terminal.id().as_bytes(),
        first_height,
        proof_context_digest: evidence.context_digest,
        successor_context_digest,
        authority_digest,
        record_digest,
    })
}

impl DurableNativeApplicationV0 {
    /// Read the complete retained schema-4 epoch-edge history and recursively
    /// audit every edge before returning it.  This is deliberately a
    /// read-only, owner-affine carrier: it does not mint an edge or relax the
    /// later checkpoint/two-seal/handoff finality requirement.
    pub fn read_epoch_edge_history_v1(&self) -> Result<EpochEdgeHistoryV1> {
        let _guard = self.lock_operation()?;
        reject_sqlite_sidecars_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            is_epoch_schema(schema_version(&connection)?),
            "epoch history requires schema4"
        );
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let mut stored = load_edges(&connection, &self.config)?;
        stored.sort_by_key(|edge| edge.first_height);
        let mut entries = Vec::with_capacity(stored.len());
        let mut previous_first = 0;
        for (index, edge) in stored.iter().enumerate() {
            ensure!(
                edge.first_height > previous_first,
                "epoch history first-height order"
            );
            // An unconsumed edge has no authenticated lineage carrier.  It is
            // safe as the first retained edge, but a second pending edge must
            // wait for the dedicated checkpoint/two-seal/handoff bridge.
            let lineage = if edge.phase == 0 {
                ensure!(
                    index == 0,
                    "second epoch edge requires a versioned handoff bridge"
                );
                vec![edge.binding]
            } else {
                let consumed = edge
                    .consumed
                    .context("consumed epoch history target missing")?;
                let p =
                    load_p(&connection, &consumed)?.context("consumed epoch history P missing")?;
                ensure!(
                    p.status == 1
                        && p.artifact_kind == 1
                        && p.commit_sequence == edge.consumed_sequence,
                    "consumed epoch history target phase"
                );
                decode_lineage(&p.lineage)?
            };
            ensure!(
                lineage.last() == Some(&edge.binding)
                    && lineage.len() == index + 1
                    && lineage
                        .iter()
                        .enumerate()
                        .all(|(position, binding)| stored[position].binding == *binding),
                "epoch history lineage/order"
            );
            // This recursive audit validates checkpoint identity, old/new
            // validator context, phase, and every ancestor edge.  In
            // particular, a later checkpoint without the two-seal/handoff
            // bridge cannot enter the history carrier.
            audited_lineage(&connection, &self.config, &lineage)?;
            entries.push(EpochEdgeHistoryEntryV1 {
                binding: edge.binding,
                checkpoint: edge.checkpoint.clone(),
                checkpoint_sequence: edge.checkpoint_sequence,
                terminal_height: edge.terminal_height,
                terminal_block: edge.terminal_block,
                first_height: edge.first_height,
                phase: if edge.phase == 0 {
                    EpochEdgePhaseV1::Installed
                } else {
                    EpochEdgePhaseV1::Consumed
                },
                consumed_block: edge.consumed,
                consumed_sequence: edge.consumed_sequence,
                lineage,
            });
            previous_first = edge.first_height;
        }
        // The history and metadata must be from one immutable owner view.  A
        // concurrent writer makes this read unusable instead of returning a
        // partially joined edge sequence.
        let after = fresh_validate_v0(&self.path, &self.config)?;
        ensure!(after == metadata, "epoch history concurrent mutation");
        Ok(EpochEdgeHistoryV1 {
            owner: Arc::clone(&self.owner_affinity),
            application_head: metadata.head,
            entries,
        })
    }

    /// Verify original successor bytes under the owner's exact retained prefix.
    /// This read-only adapter grants neither an edge nor a persistence receipt.
    /// Its sole caller must freshly inspect the owner context before creating
    /// an owner-affine checkpoint observation from these cryptographic facts.
    pub(crate) fn verify_retained_successor_evidence_v1(
        &self,
        context: &LaterEpochCheckpointContextV1,
        evidence: trnm_consensus_types::EpochActivationEvidencePreimagesV0<'_>,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0> {
        ensure!(
            context.belongs_to_application(self),
            "successor evidence foreign owner"
        );
        let _guard = self.lock_operation()?;
        reject_sqlite_sidecars_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
        verify_schema_v0(&connection)?;
        live_export::screen_legacy_export_inputs(&connection)?;
        let selected_schema = schema_version(&connection)?;
        ensure!(
            is_epoch_schema(selected_schema),
            "successor requires explicit epoch schema"
        );
        let metadata = load_metadata_v0(&connection, &self.config)?;
        ensure!(
            metadata.head == *context.application_head(),
            "successor evidence stale head"
        );
        let parent = load_p(
            &connection,
            context.application_head().block_id().as_bytes(),
        )?
        .context("successor evidence parent missing")?;
        ensure!(
            parent.target_head()? == *context.application_head()
                && parent.lineage == encode_lineage(context.lineage())?
                && context.lineage().last() == Some(&context.predecessor_edge())
                && context.context_digest()
                    == context_digest(
                        self.config.store_id,
                        context.application_head(),
                        parent
                            .commit_sequence
                            .context("successor evidence parent uncommitted")?,
                        &parent.target_set,
                        &parent.target_parameters,
                        &parent.lineage,
                    ),
            "successor evidence exact owner context"
        );
        let prefix = lineage_resolver::resolve(&connection, &self.config, context.lineage())?;
        let (set, parameters) = prefix.active(&self.config);
        ensure!(
            set == context.old_validator_set() && parameters == context.old_parameters(),
            "successor evidence authenticated configuration"
        );
        let audit = lineage_resolver::verify_successor_evidence(
            &connection,
            &self.config,
            &prefix,
            &parent,
            evidence,
            budget,
        )?;
        connection.execute_batch("ROLLBACK")?;
        #[cfg(unix)]
        self.confirm_namespace_identity_v1()?;
        Ok(audit.activation)
    }

    /// Reconstruct the authenticated old configuration and exact geometry for
    /// the next epoch checkpoint. This is a read-only planning boundary: it
    /// does not prepare a block, consume an edge, or verify caller proof. The
    /// cutoff may still be ahead of the committed head; the eventual bridge
    /// must re-open and prove that historical version before mutation.
    /// Later checkpoints must use this context rather than the legacy epoch-0
    /// configuration captured in `self.config`.
    pub fn inspect_later_epoch_checkpoint_context_v1(
        &self,
    ) -> Result<LaterEpochCheckpointContextV1> {
        let _guard = self.lock_operation()?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            is_epoch_schema(schema_version(&connection)?),
            "later checkpoint context requires schema4"
        );
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let row = connection.query_row(
            "SELECT store_id,head_block,head_root,head_commit_id,head_height,\
                    head_commit_sequence,active_set,active_parameters,edge_lineage,context_digest \
             FROM native_application_epoch_context_v1 WHERE singleton=1",
            [],
            |r| {
                Ok((
                    col32(r, "store_id")?,
                    col32(r, "head_block")?,
                    col32(r, "head_root")?,
                    col32(r, "head_commit_id")?,
                    col64(r, "head_height")?,
                    col64(r, "head_commit_sequence")?,
                    r.get::<_, Vec<u8>>("active_set")?,
                    r.get::<_, Vec<u8>>("active_parameters")?,
                    r.get::<_, Vec<u8>>("edge_lineage")?,
                    col32(r, "context_digest")?,
                ))
            },
        )?;
        // Preparing genuine descendants advances the global operation counter
        // without changing the committed epoch context. Bind its sequence to
        // the actual committed head P, never to the latest speculative append.
        let committed_head = load_p(&connection, metadata.head.block_id().as_bytes())?
            .context("later checkpoint context committed head P missing")?;
        ensure!(
            committed_head.status == 1
                && committed_head.target_head()? == metadata.head
                && committed_head.commit_sequence == Some(row.5)
                && row.5 <= metadata.durable_sequence
                && row.0 == self.config.store_id
                && row.1 == *metadata.head.block_id().as_bytes()
                && row.2 == *metadata.head.state_root().as_bytes()
                && row.3 == *metadata.head.commit_id().as_bytes()
                && row.4 == metadata.head.height().get(),
            "later checkpoint context head differs from metadata"
        );
        let lineage = decode_lineage(&row.8)?;
        let prefix = lineage_resolver::resolve(&connection, &self.config, &lineage)?;
        let predecessor = prefix
            .entries
            .last()
            .context("later checkpoint requires a retained epoch edge")?;
        ensure!(
            predecessor.phase == 1,
            "later checkpoint requires a consumed predecessor edge"
        );
        let predecessor_edge = predecessor.binding;
        let old_validator_set = predecessor.audit.activation.new_validator_set().clone();
        let old_parameters = *predecessor.audit.activation.new_consensus_parameters();
        ensure!(
            row.6
                == old_validator_set
                    .try_cev0_bytes()
                    .map_err(|e| anyhow::anyhow!("later context set encoding: {e:?}"))?
                && row.7 == old_parameters.canonical_bytes(),
            "later checkpoint context differs from authenticated prefix"
        );
        ensure!(
            row.9
                == context_digest(
                    self.config.store_id,
                    &metadata.head,
                    row.5,
                    &row.6,
                    &row.7,
                    &row.8,
                ),
            "later checkpoint context digest mismatch"
        );
        ensure!(
            old_validator_set.chain_id() == self.config.validator_set.chain_id()
                && old_validator_set.genesis_hash() == self.config.validator_set.genesis_hash()
                && old_validator_set.protocol_version()
                    == self.config.validator_set.protocol_version()
                && old_validator_set.consensus_parameters_hash() == old_parameters.hash(),
            "later checkpoint active configuration identity mismatch"
        );
        let geometry =
            trnm_consensus_types::EpochGeometryV0::new(old_validator_set.epoch(), &old_parameters)
                .map_err(|e| anyhow::anyhow!("later checkpoint geometry: {e:?}"))?;
        ensure!(
            old_validator_set.epoch() > self.config.validator_set.epoch(),
            "later checkpoint is not a successor epoch"
        );
        ensure!(
            geometry.checkpoint_height().get() > metadata.head.height().get(),
            "later checkpoint is not ahead of committed head"
        );
        let cutoff = geometry
            .checkpoint_height()
            .get()
            .checked_sub(old_parameters.snapshot_lead_blocks())
            .context("later checkpoint cutoff underflow")?;
        ensure!(
            cutoff < geometry.checkpoint_height().get(),
            "later checkpoint cutoff is outside checkpoint geometry"
        );
        let after = fresh_validate_v0(&self.path, &self.config)?;
        ensure!(
            after == metadata,
            "later checkpoint context concurrent mutation"
        );
        Ok(LaterEpochCheckpointContextV1 {
            owner: Arc::clone(&self.owner_affinity),
            application_head: metadata.head,
            predecessor_edge,
            lineage,
            old_validator_set,
            old_parameters,
            epoch: geometry.epoch(),
            checkpoint_height: geometry.checkpoint_height(),
            seal_1_height: geometry.seal_1_height(),
            seal_2_height: geometry.seal_2_height(),
            first_application_height: geometry
                .seal_2_height()
                .checked_next()
                .map_err(|e| anyhow::anyhow!("later checkpoint activation height: {e:?}"))?,
            cutoff_height: trnm_consensus_types::Height::new(cutoff),
            context_digest: row.9,
        })
    }

    /// Fail-closed entry point reserved for the later checkpoint/two-seal/
    /// handoff implementation. Keeping this explicit prevents callers from
    /// routing a later checkpoint through the epoch-0 API or treating a
    /// syntactically valid proof as a durable edge.
    pub fn require_later_epoch_checkpoint_bridge_v1(
        &self,
        context: &LaterEpochCheckpointContextV1,
    ) -> Result<()> {
        ensure!(
            context.belongs_to_application(self),
            "later checkpoint context belongs to another owner"
        );
        let fresh = self.inspect_later_epoch_checkpoint_context_v1()?;
        ensure!(
            fresh.context_digest == context.context_digest
                && fresh.application_head == context.application_head
                && fresh.predecessor_edge == context.predecessor_edge,
            "later checkpoint context is stale"
        );
        anyhow::bail!(
            "later checkpoint/two-seal/handoff bridge is not implemented; no durable authority issued"
        )
    }

    /// Inspect one retained later successor using the complete authenticated
    /// prefix. Stored coordinates are compared to strict activation-derived
    /// facts before they can enter an owner-affine recovery capability.
    pub fn inspect_later_epoch_application_edge_requirements_v1(
        &self,
        checkpoint_block: [u8; 32],
    ) -> Result<LaterEpochApplicationEdgeRequirementsV1> {
        let _guard = self.lock_operation()?;
        reject_sqlite_sidecars_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            has_later_schema(schema_version(&connection)?),
            "later application edge requirements need schema8"
        );
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let p = load_p(&connection, &checkpoint_block)?
            .context("later application edge checkpoint P missing")?;
        ensure!(
            p.status == 1 && decode_header(&p.header)?.block_kind() == BlockKind::EpochCheckpoint,
            "later application edge requires a committed checkpoint P"
        );
        validate_p(&connection, &self.config, &p)?;
        let binding = connection.query_row(
            "SELECT successor_binding FROM native_later_epoch_edge_v1 WHERE checkpoint_block=?1",
            [checkpoint_block.as_slice()],
            |row| col32(row, "successor_binding"),
        )?;
        let mut ids = decode_lineage(&p.lineage)?;
        ids.push(binding);
        let prefix = lineage_resolver::resolve(&connection, &self.config, &ids)?;
        let selected = prefix
            .entries
            .last()
            .context("later application edge prefix missing")?;
        let facts = selected
            .later_facts
            .context("later application edge selected legacy row")?;
        if selected.phase == 0 {
            ensure!(
                metadata.head == selected.checkpoint,
                "later application edge requires the committed checkpoint head"
            );
        } else {
            let consumed = load_p(
                &connection,
                &selected
                    .consumed
                    .context("later application edge consumed block missing")?,
            )?
            .context("later application edge consumed P missing")?;
            validate_consumed_later_ancestry_v1(
                &connection,
                &self.config,
                &metadata.head,
                &consumed,
            )?;
        }
        ensure!(
            fresh_validate_v0(&self.path, &self.config)? == metadata,
            "later application edge concurrent mutation"
        );
        Ok(LaterEpochApplicationEdgeRequirementsV1 {
            owner: Arc::clone(&self.owner_affinity),
            predecessor_edge: facts.predecessor_edge,
            successor_binding: facts.successor_binding,
            checkpoint_block: facts.checkpoint_block,
            checkpoint_height: facts.checkpoint_height,
            terminal_height: facts.terminal_height,
            terminal_block: facts.terminal_block,
            first_application_height: facts.first_height,
            checkpoint_commit_sequence: facts.checkpoint_commit_sequence,
            proof_context_digest: facts.proof_context_digest,
            successor_context_digest: facts.successor_context_digest,
        })
    }

    /// Reopen the durable successor edge after rechecking every requirement.
    /// The returned capability identifies the C18→C21 edge; callers use the
    /// request/header-based preparation method for candidate C+3 execution.
    pub fn require_later_epoch_application_edge_v1(
        &self,
        requirements: &LaterEpochApplicationEdgeRequirementsV1,
    ) -> Result<LaterEpochApplicationEdgeV1> {
        ensure!(
            requirements.belongs_to_application(self),
            "later application edge requirements belong to another owner"
        );
        self.recover_later_epoch_application_edge_v1(requirements)
    }

    /// Reopen the separately persisted successor edge.  This capability is
    /// owner-affine and is reconstructed only after the complete schema-8
    /// ledger (including strict CEV0 authority) has been audited.
    pub fn recover_later_epoch_application_edge_v1(
        &self,
        requirements: &LaterEpochApplicationEdgeRequirementsV1,
    ) -> Result<LaterEpochApplicationEdgeV1> {
        ensure!(
            requirements.belongs_to_application(self),
            "later successor edge requirements belong to another owner"
        );
        let fresh = self
            .inspect_later_epoch_application_edge_requirements_v1(requirements.checkpoint_block)?;
        ensure!(
            fresh.predecessor_edge == requirements.predecessor_edge
                && fresh.successor_binding == requirements.successor_binding
                && fresh.checkpoint_block == requirements.checkpoint_block
                && fresh.checkpoint_height == requirements.checkpoint_height
                && fresh.terminal_height == requirements.terminal_height
                && fresh.terminal_block == requirements.terminal_block
                && fresh.first_application_height == requirements.first_application_height
                && fresh.checkpoint_commit_sequence == requirements.checkpoint_commit_sequence
                && fresh.proof_context_digest == requirements.proof_context_digest
                && fresh.successor_context_digest == requirements.successor_context_digest,
            "later successor edge requirements are stale"
        );
        let _guard = self.lock_operation()?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            has_later_schema(schema_version(&connection)?) && later_table_installed(&connection)?,
            "later successor edge ledger missing"
        );
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let row = connection.query_row(
            "SELECT successor_binding,predecessor_edge,checkpoint_block,checkpoint_p_digest,
                    checkpoint_commit_sequence,checkpoint_height,checkpoint_root,checkpoint_commit_id,terminal_height,
                    terminal_block,first_height,proof_context_digest,successor_context_digest,
                    authority_digest,phase,record_digest
             FROM native_later_epoch_edge_v1 WHERE checkpoint_block=?1",
            [requirements.checkpoint_block.as_slice()],
            |row| {
                Ok((
                    col32(row, "successor_binding")?,
                    col32(row, "predecessor_edge")?,
                    col32(row, "checkpoint_block")?,
                    col32(row, "checkpoint_p_digest")?,
                    col64(row, "checkpoint_commit_sequence")?,
                    col64(row, "checkpoint_height")?,
                    col32(row, "checkpoint_root")?,
                    col32(row, "checkpoint_commit_id")?,
                    col64(row, "terminal_height")?,
                    col32(row, "terminal_block")?,
                    col64(row, "first_height")?,
                    col32(row, "proof_context_digest")?,
                    col32(row, "successor_context_digest")?,
                    col32(row, "authority_digest")?,
                    row.get::<_, i64>("phase")?,
                    col32(row, "record_digest")?,
                ))
            },
        )?;
        Ok(LaterEpochApplicationEdgeV1 {
            owner: Arc::clone(&self.owner_affinity),
            successor_binding: row.0,
            predecessor_edge: row.1,
            checkpoint_block: row.2,
            checkpoint_p_digest: row.3,
            checkpoint_commit_sequence: row.4,
            checkpoint_height: row.5,
            checkpoint_root: row.6,
            checkpoint_commit_id: row.7,
            terminal_height: row.8,
            terminal_block: row.9,
            first_height: row.10,
            proof_context_digest: row.11,
            successor_context_digest: row.12,
            authority_digest: row.13,
            record_digest: row.15,
        })
    }

    /// Rebuild the full later transition context from the committed proof
    /// ledger.  Compact edge coordinates alone never authorize execution:
    /// the old/new configuration and terminal header are decoded and checked
    /// against the exact retained CEV0 authority on every call.
    fn open_later_epoch_execution_context_v1(
        &self,
        edge: &LaterEpochApplicationEdgeV1,
    ) -> Result<LaterEpochExecutionContextV1> {
        ensure!(
            edge.belongs_to_application(self),
            "later execution edge belongs to another owner"
        );
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            has_later_schema(schema_version(&connection)?) && later_table_installed(&connection)?,
            "later execution requires schema8 successor ledger"
        );
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let p = load_p(&connection, &edge.checkpoint_block)?
            .context("later execution checkpoint P missing")?;
        ensure!(
            p.status == 1
                && p.p_digest == edge.checkpoint_p_digest
                && p.commit_sequence == Some(edge.checkpoint_commit_sequence),
            "later execution checkpoint P binding"
        );
        if p.target_head()? != metadata.head {
            let (phase, consumed_block): (i64, Option<Vec<u8>>) = connection.query_row(
                "SELECT phase,consumed_block FROM native_later_epoch_edge_v1 WHERE successor_binding=?1",
                [edge.successor_binding.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let consumed_block: [u8; 32] = consumed_block
                .context("later execution consumed block missing")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("later execution consumed block width"))?;
            let consumed = load_p(&connection, &consumed_block)?
                .context("later execution consumed P missing")?;
            ensure!(phase == 1, "later execution successor is not consumed");
            validate_consumed_later_ancestry_v1(
                &connection,
                &self.config,
                &metadata.head,
                &consumed,
            )?;
        }
        let mut ids = decode_lineage(&p.lineage)?;
        ensure!(
            ids.last() == Some(&edge.predecessor_edge),
            "later execution predecessor lineage"
        );
        ids.push(edge.successor_binding);
        let prefix = lineage_resolver::resolve(&connection, &self.config, &ids)?;
        let selected = prefix
            .entries
            .last()
            .context("later execution prefix missing")?;
        let facts = selected
            .later_facts
            .context("later execution selected edge is legacy")?;
        ensure!(
            facts.successor_binding == edge.successor_binding
                && facts.predecessor_edge == edge.predecessor_edge
                && facts.checkpoint_block == edge.checkpoint_block
                && facts.checkpoint_p_digest == edge.checkpoint_p_digest
                && facts.checkpoint_commit_sequence == edge.checkpoint_commit_sequence
                && facts.checkpoint_height == edge.checkpoint_height
                && facts.checkpoint_root == edge.checkpoint_root
                && facts.checkpoint_commit_id == edge.checkpoint_commit_id
                && facts.terminal_height == edge.terminal_height
                && facts.terminal_block == edge.terminal_block
                && facts.first_height == edge.first_height
                && facts.proof_context_digest == edge.proof_context_digest
                && facts.successor_context_digest == edge.successor_context_digest
                && facts.authority_digest == edge.authority_digest
                && facts.record_digest == edge.record_digest,
            "later execution edge substituted"
        );
        selected.context()
    }

    /// Derive commitments for the first application block after a later
    /// handoff without persisting a P or consuming the successor edge.
    pub fn preview_later_epoch_block_v1(
        &self,
        edge: &LaterEpochApplicationEdgeV1,
        request: &trnm_native_application::NativeEpochBlockPreviewRequestV1,
    ) -> Result<NativeBlockPreviewV0> {
        ensure!(
            edge.belongs_to_application(self),
            "later successor edge belongs to another owner"
        );
        let context = self.open_later_epoch_execution_context_v1(edge)?;
        context.validate_request_v1(request)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let checkpoint = load_p(&connection, &edge.checkpoint_block)?
            .context("later preview checkpoint P missing")?;
        ensure!(
            checkpoint.status == 1
                && checkpoint.p_digest == edge.checkpoint_p_digest
                && checkpoint.commit_sequence == Some(edge.checkpoint_commit_sequence)
                && checkpoint.target_head()? == metadata.head,
            "later preview checkpoint is not current"
        );
        let target = validate_p(&connection, &self.config, &checkpoint)?;
        crate::complete::preview_complete_epoch_block_with_context_v1(&target, &context, request)
    }

    /// Prepare the first application block after a later epoch handoff.
    ///
    /// The sealed successor context supplies the C18 application parent, the
    /// C+2 consensus parent, and the new validator/configuration.  The
    /// resulting P is still inert until `commit_epoch_finality_bytes_v1`
    /// verifies a strict proof; that commit consumes the successor edge in the
    /// same SQLite transaction as metadata and P.
    pub fn prepare_later_epoch_first_new_block_v1(
        &self,
        edge: &LaterEpochApplicationEdgeV1,
        request: NativeEpochBlockExecutionRequestV1,
        header: &BlockHeader,
    ) -> Result<PreparedNativeEpochExecutionV1> {
        ensure!(
            edge.belongs_to_application(self),
            "later successor edge belongs to another owner"
        );
        let context = self.open_later_epoch_execution_context_v1(edge)?;
        context.validate_request_v1(request.preview())?;
        ensure!(
            header.block_kind() == BlockKind::EpochHandoff
                && header.next_epoch_commitment_hash().is_none(),
            "later first-new header kind"
        );
        ensure!(
            header.id().as_bytes() == request.block_id().as_bytes()
                && header.height().get() == request.preview().height().get()
                && header.parent_id().as_bytes()
                    == request.preview().consensus_parent_id().as_bytes()
                && header.timestamp_ms() == request.preview().timestamp_ms(),
            "later first-new header/request binding"
        );
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let checkpoint = load_p(&connection, &edge.checkpoint_block)?
            .context("later first-new checkpoint P missing")?;
        ensure!(
            checkpoint.status == 1
                && checkpoint.p_digest == edge.checkpoint_p_digest
                && checkpoint.commit_sequence == Some(edge.checkpoint_commit_sequence)
                && checkpoint.target_head()? == metadata.head,
            "later first-new checkpoint is not current"
        );
        let target = validate_p(&connection, &self.config, &checkpoint)?;
        let prior_prefix = lineage_resolver::resolve(
            &connection,
            &self.config,
            &decode_lineage(&checkpoint.lineage)?,
        )?;
        self.require_prefix_preparations_v1(&prior_prefix)?;
        let prior_contexts = prior_prefix.contexts()?;
        drop(connection);
        let computed = crate::complete::compute_complete_epoch_native_block_with_context_v1(
            &target,
            &context,
            request.preview(),
        )?;
        let expected = trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
            Hash32V0::new(computed.payload_root),
            StateRootV0::new(computed.post_state_root)?,
            trnm_native_application::ReceiptsRootV0::new(computed.receipts_root)?,
            Hash32V0::new(computed.evidence_root),
        )?;
        ensure_roots(header, expected)?;
        let executed =
            NativeExecutedEpochBlockV1::new(request, expected, computed.native_receipts)?;
        let artifact =
            trnm_native_application::encode_native_executed_epoch_block_artifact_v1(&executed)?;
        let mut target = target;
        target.apply_complete_state_plan_v0(computed.plan)?;
        for replay in computed.replay_identities {
            target.mark_committed_command_v0(
                replay.command_id(),
                replay.signer_id(),
                replay.nonce(),
            )?;
        }
        let mut lineage = decode_lineage(&checkpoint.lineage)?;
        ensure!(
            lineage.last() == Some(&edge.predecessor_edge),
            "later first-new predecessor lineage"
        );
        let mut contexts: Vec<&dyn EpochExecutionContextV1> =
            prior_contexts.iter().map(|prior| prior.as_ref()).collect();
        contexts.push(&context);
        let snapshot = target.encode_epoch_authenticated_snapshot_for_context_v1(&contexts)?;
        let (commands, nonces) = target.replay_sets_v0();
        lineage.push(edge.successor_binding);
        let lineage = encode_lineage(&lineage)?;
        let row = StoredEpochPV1 {
            store_id: self.config.store_id,
            p_sequence: 0,
            status: 0,
            artifact_kind: 1,
            artifact_digest: sha256_v0(&artifact),
            artifact,
            header: header
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("later first-new header encode: {e:?}"))?,
            parent_kind: 1,
            parent: context.application_parent_v1().clone(),
            parent_p_digest: Some(checkpoint.p_digest),
            consensus_parent_height: context.consensus_parent_v1().height().get(),
            consensus_parent_block: *context.consensus_parent_v1().id().as_bytes(),
            target_height: executed.request().preview().height().get(),
            block_id: *executed.request().block_id().as_bytes(),
            lineage_digest: sha256_v0(&lineage),
            lineage,
            snapshot_digest: sha256_v0(&snapshot),
            snapshot,
            commands: borsh::to_vec(commands)?,
            nonces: borsh::to_vec(nonces)?,
            lifecycle: serde_json::to_vec(&computed.final_lifecycle)?,
            target_set: context
                .new_validator_set_v1()
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("later first-new set encode: {e:?}"))?,
            target_parameters: context.new_parameters_v1().canonical_bytes(),
            p_digest: [0; 32],
            commit_sequence: None,
            commit_id: None,
        };
        self.persist_epoch_p(row)
    }

    /// Legacy name retained as a fail-closed audit-only operation. Callers
    /// must provide the exact request/header to create a first-new P through
    /// `prepare_later_epoch_first_new_block_v1`.
    pub fn execute_later_epoch_first_new_block_v1(
        &self,
        edge: &LaterEpochApplicationEdgeV1,
    ) -> Result<()> {
        ensure!(
            edge.belongs_to_application(self),
            "later successor edge belongs to another owner"
        );
        // Re-audit the retained CEV0 configuration before returning the
        // intentional fail-closed result. Compact coordinates alone never
        // constitute execution authority.
        let _context = self.open_later_epoch_execution_context_v1(edge)?;
        anyhow::bail!(
            "later successor first-new execution bridge is not implemented; edge remains installed"
        )
    }

    /// Recover one edge selected by its validated history position.  The
    /// history is read again after reconstruction so an edge replacement or
    /// lineage mutation cannot be hidden behind a stale index.
    pub fn recover_epoch_application_edge_at_index_v1(
        &self,
        index: usize,
    ) -> Result<crate::AuthenticatedEpochApplicationEdgeV1> {
        let before = self.read_epoch_edge_history_v1()?;
        let binding = before
            .entries()
            .get(index)
            .map(EpochEdgeHistoryEntryV1::binding)
            .context("epoch history index missing")?;
        let edge = self.recover_epoch_application_edge_v1(binding)?;
        let after = self.read_epoch_edge_history_v1()?;
        ensure!(
            before.application_head == after.application_head && before.entries == after.entries,
            "epoch history changed during recovery"
        );
        Ok(edge)
    }

    /// Read one committed schema-4 ordinary descendant by application
    /// height.  This bridge is intentionally narrower than the frozen-v0
    /// finalized-read API: it accepts only `artifact_kind=0` with a Regular
    /// header and no next-epoch commitment.  Checkpoint/handoff rows remain
    /// fail-closed until their dedicated finality bridge is specified.
    pub fn read_finalized_by_height_v1(
        &self,
        height: HeightV0,
    ) -> Result<FinalizedNativeEpochApplicationReadV1> {
        let _guard = self.lock_operation()?;
        ensure!(height.get() > 0, "schema4 finalized read genesis");
        reject_sqlite_sidecars_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            is_epoch_schema(schema_version(&connection)?),
            "schema4 finalized read requires schema4"
        );
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let p = load_committed_p_by_height(&connection, height.get())?
            .context("schema4 finalized read missing committed height")?;
        ensure!(
            p.status == 1
                && p.commit_sequence.is_some()
                && p.commit_id == Some(p.commit_identity())
                && p.target_height == height.get()
                && p.target_height <= metadata.head.height().get(),
            "schema4 finalized read row is not committed"
        );
        ensure!(
            p.artifact_kind == 0,
            "schema4 finalized read checkpoint/handoff bridge required"
        );
        let header = decode_header(&p.header)?;
        ensure!(
            header.block_kind() == BlockKind::Regular
                && header.next_epoch_commitment_hash().is_none(),
            "schema4 finalized read checkpoint/handoff bridge required"
        );
        // Validate lineage, replay state, snapshot, parent binding, and exact
        // receipt roots before exposing any artifact bytes to the caller.
        validate_p(&connection, &self.config, &p)?;
        let target = p.target_head()?;
        ensure!(
            p.commit_id == Some(*target.commit_id().as_bytes()),
            "schema4 finalized read commit identity mismatch"
        );
        let executed = decode_native_executed_block_artifact_v0(&p.artifact)?;
        ensure_finalized_header_binding_v0(&header, executed.request())?;
        let receipt_commitments = executed
            .receipts()
            .iter()
            .map(|receipt| Hash32V0::new(*receipt.commitment().as_bytes()))
            .collect::<Vec<_>>();
        let prefix =
            lineage_resolver::resolve(&connection, &self.config, &decode_lineage(&p.lineage)?)?;
        let coordinates = prefix
            .entries
            .iter()
            .map(|entry| entry.audit.coordinates(entry.binding))
            .collect::<Result<Vec<_>>>()?;
        // A fresh immutable validation closes the read's TOCTOU window. Any
        // metadata/sequence change means this response is not coherent.
        let after = fresh_validate_v0(&self.path, &self.config)?;
        ensure!(
            after == metadata,
            "schema4 finalized read concurrent mutation"
        );
        Ok(FinalizedNativeEpochApplicationReadV1 {
            owner: Arc::clone(&self.owner_affinity),
            confirmed_head: metadata.head,
            row: p,
            executed,
            receipt_commitments,
            coordinates,
        })
    }

    /// Retain exact evidence before a first-new preparation. This does not
    /// consume an edge or modify application state/sequence.
    pub fn install_epoch_application_edge_v1(
        &self,
        edge: &crate::AuthenticatedEpochApplicationEdgeV1,
    ) -> Result<()> {
        let _source = self.open_epoch_checkpoint_store_v1(edge)?;
        let evidence = edge.recovery_evidence().encode()?;
        let _guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            is_epoch_schema(schema_version(&connection)?),
            "explicit epoch schema migration required"
        );
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        ensure!(
            &metadata.head == edge.application_parent(),
            "epoch installation predecessor changed"
        );
        let prior = load_edges(&connection, &self.config)?;
        if let Some(existing) = prior.iter().find(|e| e.binding == edge.authorization_id()) {
            ensure!(
                existing.evidence.encode()? == evidence
                    && existing.checkpoint == *edge.application_parent()
                    && existing.phase == 0,
                "conflicting epoch installation retry"
            );
            return Ok(());
        }
        ensure!(
            prior.len() < MAX_EDGES
                && prior
                    .iter()
                    .all(|e| e.first_height != edge.first_application_height()),
            "epoch edge conflict/capacity"
        );
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO native_epoch_edge_v1 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,NULL,NULL)",
            params![
                edge.authorization_id().as_slice(),
                self.config.store_id.as_slice(),
                edge.application_parent()
                    .height()
                    .get()
                    .to_be_bytes()
                    .as_slice(),
                edge.application_parent().block_id().as_bytes().as_slice(),
                edge.application_parent().state_root().as_bytes().as_slice(),
                edge.application_parent().commit_id().as_bytes().as_slice(),
                edge.durable_checkpoint().p_digest_v0().as_slice(),
                edge.checkpoint_commit_sequence().to_be_bytes().as_slice(),
                edge.consensus_parent()
                    .height()
                    .get()
                    .to_be_bytes()
                    .as_slice(),
                edge.consensus_parent().id().as_bytes().as_slice(),
                edge.first_application_height().to_be_bytes().as_slice(),
                &evidence,
                sha256_v0(&evidence).as_slice()
            ],
        )?;
        tx.commit()?;
        drop(connection);
        sync_store_commit_boundary_v0(&self.path)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            load_edges(&connection, &self.config)?
                .iter()
                .any(|r| r.binding == edge.authorization_id()
                    && r.evidence.encode().ok().as_ref() == Some(&evidence)),
            "epoch install fresh readback"
        );
        Ok(())
    }
}

fn audited_lineage(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    ids: &[[u8; 32]],
) -> Result<Vec<([u8; 32], crate::epoch_recovery::AuditedEpochEvidenceV1)>> {
    audited_lineage_with_read_policy(connection, config, ids, EpochReadPolicyV1::Physical)
}

fn audited_lineage_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    ids: &[[u8; 32]],
    policy: EpochReadPolicyV1<'_>,
) -> Result<Vec<([u8; 32], crate::epoch_recovery::AuditedEpochEvidenceV1)>> {
    Ok(lineage_resolver::resolve_with_read_policy(connection, config, ids, policy)?.into_audits())
}

fn validate_epoch_descendant_kind(header: &BlockHeader) -> Result<()> {
    match header.block_kind() {
        BlockKind::Regular => {
            ensure!(
                header.next_epoch_commitment_hash().is_none(),
                "ordinary sparse descendant carries an epoch commitment"
            );
            Ok(())
        }
        BlockKind::EpochCheckpoint => {
            ensure!(
                header.next_epoch_commitment_hash().is_some(),
                "epoch checkpoint is missing its next-epoch commitment"
            );
            Ok(())
        }
        _ => anyhow::bail!("epoch descendant kind requires a dedicated seal/handoff bridge"),
    }
}

fn validate_p(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
) -> Result<InMemoryNativeExecutionStoreV0> {
    validate_p_with_read_policy(connection, config, p, EpochReadPolicyV1::Physical)
}

fn validate_p_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    policy: EpochReadPolicyV1<'_>,
) -> Result<InMemoryNativeExecutionStoreV0> {
    validate_p_with_seen_and_policy(connection, config, p, &mut BTreeSet::new(), policy)
}

/// Audit a schema-8 successor binding into the same strict activation carrier
/// used by legacy lineage validation.  This is an internal representation
/// join only; it does not mint the public legacy edge capability.
pub(super) fn audit_later_successor_for_lineage_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    binding: [u8; 32],
    predecessor: [u8; 32],
    policy: EpochReadPolicyV1<'_>,
) -> Result<crate::epoch_recovery::AuditedEpochEvidenceV1> {
    let checkpoint = connection.query_row(
        "SELECT checkpoint_block FROM native_later_epoch_edge_v1 WHERE successor_binding=?1",
        [binding.as_slice()],
        |row| col32(row, "checkpoint_block"),
    )?;
    let p = load_p(connection, &checkpoint)?.context("later successor lineage P missing")?;
    let mut ids = decode_lineage(&p.lineage)?;
    ensure!(
        ids.last() == Some(&predecessor),
        "later successor predecessor mismatch"
    );
    ids.push(binding);
    let mut prefix = lineage_resolver::resolve_with_read_policy(connection, config, &ids, policy)?;
    let selected = prefix
        .entries
        .pop()
        .context("later successor prefix empty")?;
    ensure!(
        selected.later_facts.is_some(),
        "later successor ownership mismatch"
    );
    Ok(*selected.audit)
}

fn validate_p_with_seen_and_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    _seen: &mut BTreeSet<[u8; 32]>,
    policy: EpochReadPolicyV1<'_>,
) -> Result<InMemoryNativeExecutionStoreV0> {
    ensure!(
        p.store_id == config.store_id
            && p.p_sequence > 1
            && matches!(p.artifact_kind, 0 | 1)
            && matches!(p.parent_kind, 0 | 1)
            && matches!(p.status, 0 | 1)
            && ((p.parent_kind == 0 && p.parent_p_digest.is_none())
                || (p.parent_kind == 1 && p.parent_p_digest.is_some())),
        "epoch P source/tags"
    );
    ensure!(
        p.artifact_digest == sha256_v0(&p.artifact)
            && p.snapshot_digest == sha256_v0(&p.snapshot)
            && p.lineage_digest == sha256_v0(&p.lineage)
            && p.p_digest == p.digest()?,
        "epoch P digest mismatch"
    );
    ensure!(
        (p.status == 0 && p.commit_sequence.is_none() && p.commit_id.is_none())
            || (p.status == 1
                && p.commit_sequence.is_some_and(|n| n > p.p_sequence)
                && p.commit_id == Some(p.commit_identity())),
        "epoch P phase binding"
    );
    let header = decode_header(&p.header)?;
    if p.status == 1 && header.block_kind() == BlockKind::EpochCheckpoint {
        ensure!(
            has_later_schema(policy.schema(connection)?),
            "committed later checkpoint requires schema8"
        );
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM native_later_epoch_finality_v1 WHERE checkpoint_block=?1 AND p_digest=?2 AND commit_sequence=?3",
            params![p.block_id.as_slice(), p.p_digest.as_slice(), p.commit_sequence.context("later sequence")?.to_be_bytes().as_slice()],
            |row| row.get(0),
        )?;
        let pre = if policy.schema(connection)? == PRE_HANDOFF_SCHEMA_VERSION {
            pre_handoff::matching_count(connection, p)?
        } else {
            0
        };
        ensure!(
            count == 1 || pre == 1,
            "committed later checkpoint proof record missing"
        );
    }
    ensure!(
        header.id().as_bytes() == &p.block_id
            && header.height().get() == p.target_height
            && header.parent_id().as_bytes() == &p.consensus_parent_block
            && header.chain_id().as_str() == config.chain_id
            && header.genesis_hash().as_bytes() == &config.genesis_hash,
        "epoch P header identity"
    );
    let lineage = decode_lineage(&p.lineage)?;
    let legacy_edges = load_edges(connection, config)?;
    let edges = audited_lineage_with_read_policy(connection, config, &lineage, policy)?;
    let (_, latest) = edges.last().context("epoch P has no lineage")?;
    ensure!(
        latest
            .activation
            .new_validator_set()
            .try_cev0_bytes()
            .map_err(|e| anyhow::anyhow!("set encoding: {e:?}"))?
            == p.target_set
            && latest
                .activation
                .new_consensus_parameters()
                .canonical_bytes()
                == p.target_parameters,
        "epoch P target configuration differs from strict edge"
    );
    let active = latest.activation.new_validator_set();
    let parameters = latest.activation.new_consensus_parameters();
    if p.parent_kind == 0 {
        if let Some(parent) = load_p(connection, p.parent.block_id().as_bytes())? {
            ensure!(
                parent.status == 1 && parent.target_head()? == p.parent,
                "epoch committed parent not committed"
            );
        } else {
            let parent = load_p_by_block_v0(connection, *p.parent.block_id().as_bytes())?
                .context("epoch committed parent missing")?;
            ensure!(
                parent.status == P_STATUS_COMMITTED
                    && parent.commit_id == Some(*p.parent.commit_id().as_bytes())
                    && parent.target_height == p.parent.height().get(),
                "legacy epoch parent not committed"
            );
        }
    }
    if let Some(expected) = p.parent_p_digest {
        let actual = match load_p(connection, p.parent.block_id().as_bytes())? {
            Some(parent) => parent.p_digest,
            None => {
                load_p_by_block_v0(connection, *p.parent.block_id().as_bytes())?
                    .context("P parent missing")?
                    .p_digest
            }
        };
        ensure!(actual == expected, "epoch P parent digest mismatch");
    }
    ensure!(
        header.validator_set_id() == active.id()
            && header.consensus_parameters_hash() == parameters.hash()
            && header.epoch() == active.epoch(),
        "epoch P header active context"
    );
    if p.artifact_kind == 1 {
        if p.status == 1 {
            let binding = *lineage.last().context("committed epoch lineage missing")?;
            if let Some(edge) = legacy_edges.iter().find(|e| e.binding == binding) {
                ensure!(
                    edge.phase == 1
                        && edge.consumed == Some(p.block_id)
                        && edge.consumed_sequence == p.commit_sequence,
                    "committed epoch edge phase mismatch"
                );
            } else {
                let (phase, consumed_block, consumed_sequence): (
                    i64,
                    Option<Vec<u8>>,
                    Option<Vec<u8>>,
                ) = connection.query_row(
                    "SELECT phase,consumed_block,consumed_sequence
                         FROM native_later_epoch_edge_v1 WHERE successor_binding=?1",
                    [binding.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                let expected_sequence = p.commit_sequence.map(|value| value.to_be_bytes().to_vec());
                ensure!(
                    phase == 1
                        && consumed_block.as_deref() == Some(p.block_id.as_slice())
                        && consumed_sequence.as_deref() == expected_sequence.as_deref(),
                    "committed later successor edge phase mismatch"
                );
            }
        }
        let executed =
            trnm_native_application::decode_native_executed_epoch_block_artifact_v1(&p.artifact)?;
        let request = executed.request();
        let preview = request.preview();
        let coords = latest.coordinates(*lineage.last().context("lineage")?)?;
        ensure!(
            header.block_kind() == trnm_consensus_types::BlockKind::EpochHandoff
                && p.target_height == coords.first_version
                && p.parent.height().get() == coords.checkpoint_version
                && p.parent.state_root().as_bytes() == &coords.checkpoint_root
                && p.consensus_parent_height == coords.terminal_version
                && preview.application_parent() == &p.parent
                && preview.consensus_parent_id().as_bytes() == &p.consensus_parent_block
                && preview.consensus_parent_height().get() == p.consensus_parent_height
                && preview.edge_binding().as_bytes() == lineage.last().context("lineage")?
                && request.block_id().as_bytes() == &p.block_id
                && preview.height().get() == p.target_height
                && preview.timestamp_ms() == header.timestamp_ms(),
            "epoch artifact parent binding"
        );
        ensure!(
            preview.chain_id().as_str() == config.chain_id
                && preview.genesis_hash().as_bytes() == &config.genesis_hash
                && preview.active_validator_set_id().as_bytes() == active.id().as_bytes(),
            "epoch artifact active context"
        );
        ensure_roots(&header, request.expected())?;
        let exact = crate::poco_checkpoint::native_execution_from_receipts_v0(
            preview.transactions(),
            executed.receipts(),
        )?;
        ensure!(
            exact
                .application_payload()
                .payload_root()
                .map_err(|e| anyhow::anyhow!("epoch payload root: {e:?}"))?
                == header.payload_root()
                && exact
                    .execution_receipts()
                    .receipts_root()
                    .map_err(|e| anyhow::anyhow!("epoch receipt root: {e:?}"))?
                    == header.receipts_root(),
            "epoch receipt roots mismatch"
        );
    } else {
        validate_epoch_descendant_kind(&header)?;
        let executed = decode_native_executed_block_artifact_v0(&p.artifact)?;
        ensure!(
            p.target_height
                == p.parent
                    .height()
                    .get()
                    .checked_add(1)
                    .context("parent exhausted")?
                && p.consensus_parent_height == p.parent.height().get()
                && &p.consensus_parent_block == p.parent.block_id().as_bytes()
                && executed.request().parent() == &p.parent,
            "ordinary sparse P parent binding"
        );
        ensure!(
            executed.request().active_validator_set_id().as_bytes() == active.id().as_bytes(),
            "ordinary sparse artifact active context"
        );
        ensure_finalized_header_binding_v0(&header, executed.request())?;
        validate_native_finalized_execution_receipts_v0(&executed)?;
    }
    let commands = decode_borsh_v0(&p.commands, "epoch_p.commands")?;
    let nonces = decode_borsh_v0(&p.nonces, "epoch_p.nonces")?;
    let coordinates = edges
        .iter()
        .map(|(binding, edge)| edge.coordinates(*binding))
        .collect::<Result<Vec<_>>>()?;
    let store = InMemoryNativeExecutionStoreV0::decode_epoch_snapshot_for_coordinates_v1(
        config.chain_id.clone(),
        config.signers.clone(),
        *parameters,
        commands,
        nonces,
        &p.snapshot,
        &coordinates,
    )?;
    ensure!(
        store.parent_version_v0()? == p.target_height
            && store.parent_root_v0()?.0 == *header.state_root().as_bytes(),
        "epoch P snapshot head"
    );
    let live = store.verified_live_values_v0(p.target_height)?;
    let lifecycle = load_validator_lifecycle_from_live_v0(&live, p.target_height)?;
    ensure!(
        serde_json::to_vec(&lifecycle)? == p.lifecycle,
        "epoch P lifecycle snapshot mismatch"
    );
    validate_application_validator_projection_v0(active, &lifecycle.active_validators)?;
    Ok(store)
}

fn ensure_roots(
    header: &BlockHeader,
    expected: trnm_native_application::NativeExpectedBlockCommitmentsV0,
) -> Result<()> {
    ensure!(
        header.payload_root().as_bytes() == expected.payload_root().as_bytes()
            && header.state_root().as_bytes() == expected.post_state_root().as_bytes()
            && header.receipts_root().as_bytes() == expected.receipts_root().as_bytes()
            && header.evidence_root().as_bytes() == expected.evidence_root().as_bytes(),
        "epoch expected header roots"
    );
    Ok(())
}

fn all_p(connection: &Connection) -> Result<Vec<StoredEpochPV1>> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_durable_execution_p_v1",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        count >= 0 && count as usize <= MAX_P_ROWS,
        "epoch P count budget"
    );
    let bytes:i64=connection.query_row("SELECT COALESCE(SUM(length(artifact)+length(target_snapshot)+length(replay_commands)+length(replay_nonces)+length(lifecycle)+length(header)+length(target_set)+length(target_parameters)+length(edge_lineage)),0) FROM native_durable_execution_p_v1",[],|r|r.get(0))?;
    ensure!(
        bytes >= 0 && bytes as usize <= MAX_PREPARED_BYTES,
        "epoch P total byte budget"
    );
    let mut stmt = connection
        .prepare("SELECT block_id FROM native_durable_execution_p_v1 ORDER BY p_sequence")?;
    let ids = stmt
        .query_map([], |r| col32(r, "block_id"))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ids.iter()
        .map(|id| load_p(connection, id)?.context("epoch P disappeared"))
        .collect()
}

pub(super) fn validate_later_inventory_v1_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    policy: EpochReadPolicyV1<'_>,
) -> Result<()> {
    let schema = policy.schema(connection)?;
    if schema == PRE_HANDOFF_SCHEMA_VERSION {
        pre_handoff::audit(connection, config)?;
    }
    if has_later_schema(schema) {
        validate_later_records_with_read_policy(connection, config, policy)?;
        // Authenticate the complete successor ledger before the application
        // proof pass. The row-specific audit below must not re-run this
        // whole-table decode while the caller is already on a deep recovery
        // stack.
        validate_later_edges_with_read_policy(connection, config, policy)?;
        // Schema 8 has no application-proof ledger; schema 9 requires it.
        if has_later_application_finality_schema(schema) {
            validate_later_application_finality_with_read_policy(connection, config, policy)?;
        }
        if has_later_descendant_finality_schema(schema) {
            descendant_finality::audit_with_read_policy(connection, config, policy)?;
        }
    }
    Ok(())
}

pub(super) fn inventory_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    policy: EpochReadPolicyV1<'_>,
) -> DurableResult<Vec<ValidatedPInventoryEntryV0>> {
    validate_later_inventory_v1_with_read_policy(connection, config, policy)
        .map_err(local_error)?;
    (|| -> Result<_> {
        // Even an installed edge not yet referenced by a P must retain valid evidence.
        for edge in load_edges(connection, config)? {
            lineage_resolver::resolve_with_read_policy(
                connection,
                config,
                &[edge.binding],
                policy,
            )?;
        }
        let values = all_p(connection)?;
        let mut rows = Vec::new();
        for p in values {
            validate_p_with_read_policy(connection, config, &p, policy)?;
            let head = p.target_head()?;
            rows.push(ValidatedPInventoryEntryV0 {
                target_height: p.target_height,
                p_sequence: p.p_sequence,
                status: if p.status == 0 {
                    P_STATUS_PREPARED
                } else {
                    P_STATUS_COMMITTED
                },
                parent_height: p.parent.height().get(),
                parent_block_id: *p.parent.block_id().as_bytes(),
                parent_state_root: *p.parent.state_root().as_bytes(),
                parent_commit_id: *p.parent.commit_id().as_bytes(),
                block_id: p.block_id,
                target_state_root: *head.state_root().as_bytes(),
                application_commit_id: *head.commit_id().as_bytes(),
                commit_sequence: p.commit_sequence,
                epoch_gap: p.artifact_kind == 1,
            });
        }
        Ok(rows)
    })()
    .map_err(local_error)
}

pub(super) fn metadata_store(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    metadata: &MetadataV0,
) -> DurableResult<InMemoryNativeExecutionStoreV0> {
    metadata_store_with_read_policy(connection, config, metadata, EpochReadPolicyV1::Physical)
}

pub(super) fn metadata_store_with_read_policy(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    metadata: &MetadataV0,
    policy: EpochReadPolicyV1<'_>,
) -> DurableResult<InMemoryNativeExecutionStoreV0> {
    (|| -> Result<_> {
        if let Some(p) = load_p(connection, metadata.head.block_id().as_bytes())? {
            ensure!(
                p.status == 1
                    && p.target_head()? == metadata.head
                    && p.snapshot == metadata.snapshot
                    && p.snapshot_digest == metadata.snapshot_digest,
                "epoch metadata differs from committed P"
            );
            let store = validate_p_with_read_policy(connection, config, &p, policy)?;
            validate_context(connection, config, &p)?;
            ensure!(
                store.replay_sets_v0().0 == &metadata.command_ids
                    && store.replay_sets_v0().1 == &metadata.signer_nonces,
                "epoch metadata replay mismatch"
            );
            Ok(store)
        } else {
            let count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM native_application_epoch_context_v1",
                [],
                |r| r.get(0),
            )?;
            ensure!(count == 0, "legacy head has epoch context");
            Ok(metadata.to_store(config)?)
        }
    })()
    .map_err(local_error)
}

impl DurableNativeApplicationV0 {
    /// Reconstructs application authority from retained raw evidence and the
    /// fresh committed checkpoint/cutoff. Checksums alone never issue an edge.
    pub fn recover_epoch_application_edge_v1(
        &self,
        binding: [u8; 32],
    ) -> Result<crate::AuthenticatedEpochApplicationEdgeV1> {
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            is_epoch_schema(schema_version(&connection)?),
            "epoch schema unavailable"
        );
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let edge = load_edges(&connection, &self.config)?
            .into_iter()
            .find(|e| e.binding == binding)
            .context("epoch edge missing")?;
        let executed =
            decode_native_executed_block_artifact_v0(&edge.evidence.checkpoint_artifact)?;
        let header = decode_header(&edge.evidence.checkpoint_header)?;
        let request = executed.request();
        let preview = NativeBlockPreviewRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            request.parent().clone(),
            request.height(),
            request.timestamp_ms(),
            request.active_validator_set_id(),
            request.transactions().to_vec(),
        )?;
        drop(connection);
        let journal = crate::poco_preparation_journal::PocoPreparationJournalV0::open_existing(
            crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&self.path),
        )?;
        journal.require_retained_bound(
            edge.evidence.preparation_id,
            &edge.evidence.checkpoint_header,
        )?;
        let prepared = self.prepare_native_poco_checkpoint_v0(
            &preview,
            header.view(),
            header.proposer_id(),
            &edge.evidence.cutoff_finality,
            &edge.evidence.cutoff_parent,
        )?;
        ensure!(
            prepared.header() == &header,
            "reconstructed checkpoint header mismatch"
        );
        journal.require_retained_bound(
            edge.evidence.preparation_id,
            &edge.evidence.checkpoint_header,
        )?;
        let confirmed = self.confirm_poco_checkpoint_v0(
            prepared,
            &edge.evidence.checkpoint_finality,
            &edge.evidence.anchor,
        )?;
        ensure!(
            confirmed.recovery_evidence.encode()? == edge.evidence.encode()?
                && confirmed.handoff_authorization_id() == binding
                && confirmed.durable_row().p_digest_v0() == edge.checkpoint_p_digest,
            "reconstructed native edge differs from retained evidence"
        );
        confirmed.into_epoch_application_edge_v1()
    }

    pub fn execute_epoch_block_v1(
        &self,
        edge: &crate::AuthenticatedEpochApplicationEdgeV1,
        request: NativeEpochBlockExecutionRequestV1,
        header: &BlockHeader,
    ) -> Result<PreparedNativeEpochExecutionV1> {
        edge.validate_request_v1(request.preview())?;
        self.install_epoch_application_edge_v1(edge)?;
        let source = self.open_epoch_checkpoint_store_v1(edge)?;
        let computed = crate::complete::compute_complete_epoch_native_block_v1(
            &source,
            edge,
            request.preview(),
        )?;
        let expected = trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
            Hash32V0::new(computed.payload_root),
            StateRootV0::new(computed.post_state_root)?,
            trnm_native_application::ReceiptsRootV0::new(computed.receipts_root)?,
            Hash32V0::new(computed.evidence_root),
        )?;
        let executed =
            NativeExecutedEpochBlockV1::new(request, expected, computed.native_receipts)?;
        let artifact =
            trnm_native_application::encode_native_executed_epoch_block_artifact_v1(&executed)?;
        let preview = executed.request().preview();
        ensure!(
            header.id().as_bytes() == executed.request().block_id().as_bytes()
                && header.height().get() == preview.height().get()
                && header.parent_id().as_bytes() == preview.consensus_parent_id().as_bytes()
                && header.timestamp_ms() == preview.timestamp_ms()
                && header.block_kind() == trnm_consensus_types::BlockKind::EpochHandoff,
            "epoch P header/request mismatch"
        );
        ensure_roots(header, expected)?;
        let mut target = source;
        target.apply_complete_state_plan_v0(computed.plan)?;
        for replay in computed.replay_identities {
            target.mark_committed_command_v0(
                replay.command_id(),
                replay.signer_id(),
                replay.nonce(),
            )?;
        }
        let snapshot = target.encode_epoch_authenticated_snapshot_v1(&[edge])?;
        let (commands, nonces) = target.replay_sets_v0();
        let lineage = encode_lineage(&[edge.authorization_id()])?;
        let row = StoredEpochPV1 {
            store_id: self.config.store_id,
            p_sequence: 0,
            status: 0,
            artifact_kind: 1,
            artifact_digest: sha256_v0(&artifact),
            artifact,
            header: header
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("epoch header encode: {e:?}"))?,
            parent_kind: 0,
            parent: edge.application_parent().clone(),
            parent_p_digest: None,
            consensus_parent_height: edge.consensus_parent().height().get(),
            consensus_parent_block: *edge.consensus_parent().id().as_bytes(),
            target_height: preview.height().get(),
            block_id: *executed.request().block_id().as_bytes(),
            lineage_digest: sha256_v0(&lineage),
            lineage,
            snapshot_digest: sha256_v0(&snapshot),
            snapshot,
            commands: borsh::to_vec(commands)?,
            nonces: borsh::to_vec(nonces)?,
            lifecycle: serde_json::to_vec(&computed.final_lifecycle)?,
            target_set: edge
                .new_validator_set()
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("epoch set encode: {e:?}"))?,
            target_parameters: edge.new_parameters().canonical_bytes(),
            p_digest: [0; 32],
            commit_sequence: None,
            commit_id: None,
        };
        self.persist_epoch_p(row)
    }

    fn require_prefix_preparations_v1(&self, prefix: &lineage_resolver::Prefix) -> Result<()> {
        if prefix
            .entries
            .iter()
            .any(|entry| entry.legacy_preparation.is_some())
        {
            let journal = crate::poco_preparation_journal::PocoPreparationJournalV0::open_existing(
                crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&self.path),
            )?;
            for entry in &prefix.entries {
                if let Some((id, header)) = &entry.legacy_preparation {
                    journal.require_retained_bound(*id, header)?;
                }
            }
        }
        Ok(())
    }

    #[inline(never)]
    fn recover_epoch_execution_contexts_v1(
        &self,
        bindings: &[[u8; 32]],
    ) -> Result<Vec<Box<dyn EpochExecutionContextV1>>> {
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let prefix = lineage_resolver::resolve(&connection, &self.config, bindings)?;
        if prefix
            .entries
            .iter()
            .any(|entry| entry.later_facts.is_some())
        {
            ensure!(
                has_later_descendant_finality_schema(schema_version(&connection)?),
                "later descendant authority requires schema10 ordinary finality"
            );
        }
        self.require_prefix_preparations_v1(&prefix)?;
        validate_prefix_current_ancestry_v1(&connection, &self.config, &metadata.head, &prefix)?;
        prefix.contexts()
    }

    pub fn execute_epoch_descendant_v1(
        &self,
        parent: &PreparedNativeEpochExecutionV1,
        request: NativeBlockExecutionRequestV0,
        header: &BlockHeader,
    ) -> Result<PreparedNativeEpochExecutionV1> {
        ensure!(
            Arc::ptr_eq(&parent.owner, &self.owner_affinity),
            "prepared epoch parent belongs to another owner"
        );
        ensure!(
            request.parent() == &parent.overlay_parent_head()?,
            "prepared descendant parent mismatch"
        );
        let bindings = decode_lineage(&parent.row.lineage)?;
        let contexts = self.recover_epoch_execution_contexts_v1(&bindings)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let actual =
            load_p(&connection, &parent.row.block_id)?.context("prepared epoch parent missing")?;
        ensure!(
            actual.p_digest == parent.row.p_digest,
            "prepared epoch parent changed"
        );
        let mut target = validate_p(&connection, &self.config, &actual)?;
        drop(connection);
        let active = contexts.last().context("prepared parent has no edge")?;
        let execution = execute_complete_native_block_v0(
            &target,
            active.new_validator_set_v1(),
            active.new_validator_set_v1().genesis_hash(),
            &request,
        )?;
        let (executed, plan, replay, lifecycle) = execution.into_parts();
        ensure_finalized_header_binding_v0(header, &request)?;
        validate_epoch_descendant_kind(header)?;
        target.apply_complete_state_plan_v0(plan)?;
        for identity in replay {
            target.mark_committed_command_v0(
                identity.command_id(),
                identity.signer_id(),
                identity.nonce(),
            )?;
        }
        let snapshot = target.encode_epoch_authenticated_snapshot_for_context_v1(
            &contexts
                .iter()
                .map(|context| context.as_ref())
                .collect::<Vec<_>>(),
        )?;
        let artifact = encode_native_executed_block_artifact_v0(&executed)?;
        let (commands, nonces) = target.replay_sets_v0();
        let row = StoredEpochPV1 {
            store_id: self.config.store_id,
            p_sequence: 0,
            status: 0,
            artifact_kind: 0,
            artifact_digest: sha256_v0(&artifact),
            artifact,
            header: header
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("descendant header: {e:?}"))?,
            parent_kind: 1,
            parent: request.parent().clone(),
            parent_p_digest: Some(actual.p_digest),
            consensus_parent_height: request.parent().height().get(),
            consensus_parent_block: *request.parent().block_id().as_bytes(),
            target_height: request.height().get(),
            block_id: *request.block_id().as_bytes(),
            lineage: actual.lineage.clone(),
            lineage_digest: actual.lineage_digest,
            snapshot_digest: sha256_v0(&snapshot),
            snapshot,
            commands: borsh::to_vec(commands)?,
            nonces: borsh::to_vec(nonces)?,
            lifecycle: serde_json::to_vec(&lifecycle)?,
            target_set: actual.target_set,
            target_parameters: actual.target_parameters,
            p_digest: [0; 32],
            commit_sequence: None,
            commit_id: None,
        };
        self.persist_epoch_p(row)
    }

    fn persist_epoch_p(&self, mut p: StoredEpochPV1) -> Result<PreparedNativeEpochExecutionV1> {
        let _guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        ensure!(
            is_epoch_schema(schema_version(&connection)?),
            "epoch schema unavailable"
        );
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        if descendant_finality::binding(&connection, &p)?.is_some() {
            ensure!(
                has_later_descendant_finality_schema(schema_version(&connection)?),
                "later descendant prepare requires schema10 ordinary finality"
            );
        }
        if let Some(existing) = load_p(&connection, &p.block_id)? {
            ensure!(
                existing.artifact == p.artifact
                    && existing.header == p.header
                    && existing.snapshot == p.snapshot
                    && existing.parent == p.parent
                    && existing.parent_kind == p.parent_kind
                    && existing.parent_p_digest == p.parent_p_digest
                    && existing.lineage == p.lineage
                    && existing.commands == p.commands
                    && existing.nonces == p.nonces
                    && existing.lifecycle == p.lifecycle
                    && existing.target_set == p.target_set
                    && existing.target_parameters == p.target_parameters
                    && existing.artifact_kind == p.artifact_kind
                    && existing.consensus_parent_height == p.consensus_parent_height
                    && existing.consensus_parent_block == p.consensus_parent_block,
                "epoch P conflicting retry"
            );
            validate_p(&connection, &self.config, &existing)?;
            drop(connection);
            sync_store_commit_boundary_v0(&self.path)?;
            fresh_validate_v0(&self.path, &self.config)?;
            let connection = open_immutable_connection_v0(&self.path)?;
            let read =
                load_p(&connection, &existing.block_id)?.context("retried epoch P missing")?;
            ensure!(
                read.p_digest == existing.p_digest,
                "retried epoch P changed"
            );
            return Ok(PreparedNativeEpochExecutionV1 {
                owner: Arc::clone(&self.owner_affinity),
                row: read,
            });
        }
        let rows = all_p(&connection)?;
        ensure!(
            rows.len() < MAX_P_ROWS
                && p.snapshot.len() <= MAX_SNAPSHOT_BYTES
                && p.commands.len() <= MAX_REPLAY_BYTES
                && p.nonces.len() <= MAX_REPLAY_BYTES
                && p.lifecycle.len() <= MAX_LIFECYCLE_BYTES,
            "epoch prepare capacity unavailable"
        );
        if p.parent_kind == 0 {
            ensure!(
                p.parent == metadata.head,
                "epoch prepare committed parent stale"
            );
        } else {
            let source = load_p(&connection, p.parent.block_id().as_bytes())?
                .context("epoch prepared parent missing")?;
            ensure!(
                p.parent_p_digest == Some(source.p_digest) && source.target_head()? == p.parent,
                "epoch prepare ancestry splice"
            );
            let mut cursor = &source;
            let mut depth = 1;
            while cursor.target_head()? != metadata.head && cursor.parent != metadata.head {
                depth += 1;
                ensure!(depth <= 8, "epoch prepared depth unavailable");
                cursor = rows
                    .iter()
                    .find(|r| r.block_id == *cursor.parent.block_id().as_bytes())
                    .context("epoch ancestor missing")?;
            }
        }
        p.p_sequence = metadata
            .durable_sequence
            .checked_add(1)
            .context("durable sequence exhausted")?;
        p.p_digest = p.digest()?;
        validate_p(&connection, &self.config, &p)?;
        let total = rows
            .iter()
            .try_fold(
                p.artifact.len()
                    + p.snapshot.len()
                    + p.commands.len()
                    + p.nonces.len()
                    + p.lifecycle.len()
                    + p.header.len()
                    + p.target_set.len()
                    + p.target_parameters.len()
                    + p.lineage.len(),
                |n, r| {
                    n.checked_add(
                        r.artifact.len()
                            + r.snapshot.len()
                            + r.commands.len()
                            + r.nonces.len()
                            + r.lifecycle.len()
                            + r.header.len()
                            + r.target_set.len()
                            + r.target_parameters.len()
                            + r.lineage.len(),
                    )
                },
            )
            .context("epoch byte count overflow")?;
        ensure!(
            total <= MAX_PREPARED_BYTES,
            "epoch prepared byte capacity unavailable"
        );
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_p(&tx, &p)?;
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=? WHERE singleton=1 AND durable_sequence=?",
            params![p.p_sequence.to_be_bytes().as_slice(),metadata.durable_sequence.to_be_bytes().as_slice()])?==1,"epoch prepare CAS conflict");
        tx.commit()?;
        drop(connection);
        sync_store_commit_boundary_v0(&self.path)?;
        let fresh = fresh_validate_v0(&self.path, &self.config)?;
        ensure!(
            fresh.head == metadata.head && fresh.durable_sequence == p.p_sequence,
            "epoch prepare readback mismatch"
        );
        let connection = open_immutable_connection_v0(&self.path)?;
        let row = load_p(&connection, &p.block_id)?.context("epoch prepared row missing")?;
        ensure!(row.p_digest == p.p_digest, "epoch prepared digest changed");
        Ok(PreparedNativeEpochExecutionV1 {
            owner: Arc::clone(&self.owner_affinity),
            row,
        })
    }

    pub fn reopen_prepared_epoch_execution_v1(
        &self,
        block: [u8; 32],
    ) -> Result<PreparedNativeEpochExecutionV1> {
        let _guard = self.lock_operation()?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
        let row = load_p(&connection, &block)?.context("epoch P missing")?;
        let prefix =
            lineage_resolver::resolve(&connection, &self.config, &decode_lineage(&row.lineage)?)?;
        self.require_prefix_preparations_v1(&prefix)?;
        validate_prefix_current_ancestry_v1(&connection, &self.config, &metadata.head, &prefix)?;
        validate_p(&connection, &self.config, &row)?;
        ensure!(
            fresh_validate_v0(&self.path, &self.config)? == metadata,
            "reopened P changed during edge reconstruction"
        );
        Ok(PreparedNativeEpochExecutionV1 {
            owner: Arc::clone(&self.owner_affinity),
            row,
        })
    }

    pub fn confirm_prepared_epoch_execution_v1(
        &self,
        prepared: &PreparedNativeEpochExecutionV1,
    ) -> Result<ConfirmedPreparedNativeEpochExecutionV1> {
        ensure!(
            Arc::ptr_eq(&prepared.owner, &self.owner_affinity),
            "epoch prepared readback foreign owner"
        );
        let fresh = self.reopen_prepared_epoch_execution_v1(prepared.row.block_id)?;
        ensure!(
            fresh.row.p_digest == prepared.row.p_digest
                && fresh.row.p_sequence == prepared.row.p_sequence
                && fresh.row.artifact == prepared.row.artifact
                && fresh.row.header == prepared.row.header,
            "epoch prepared readback substituted"
        );
        Ok(ConfirmedPreparedNativeEpochExecutionV1 { prepared: fresh })
    }
}

fn insert_p(tx: &rusqlite::Transaction<'_>, p: &StoredEpochPV1) -> Result<()> {
    let parent_digest = p.parent_p_digest.map(|v| v.to_vec());
    tx.execute("INSERT INTO native_durable_execution_p_v1 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)",params![
        p.block_id.as_slice(),p.store_id.as_slice(),p.p_sequence.to_be_bytes().as_slice(),p.status,p.artifact_kind,&p.artifact,p.artifact_digest.as_slice(),&p.header,
        p.parent_kind,p.parent.height().get().to_be_bytes().as_slice(),p.parent.block_id().as_bytes().as_slice(),p.parent.state_root().as_bytes().as_slice(),p.parent.commit_id().as_bytes().as_slice(),parent_digest,
        p.consensus_parent_height.to_be_bytes().as_slice(),p.consensus_parent_block.as_slice(),p.target_height.to_be_bytes().as_slice(),&p.lineage,p.lineage_digest.as_slice(),
        &p.snapshot,p.snapshot_digest.as_slice(),&p.commands,&p.nonces,&p.lifecycle,&p.target_set,&p.target_parameters,p.p_digest.as_slice()])?;
    Ok(())
}

/// Fresh committed application readback. It retains the live owner and the
/// exact P/commit identity; no public constructor or Clone exists.
#[must_use]
pub struct CommittedNativeEpochExecutionV1 {
    owner: Arc<()>,
    head: ApplicationHeadV0,
    p_digest: [u8; 32],
    commit_sequence: u64,
}
impl CommittedNativeEpochExecutionV1 {
    pub fn head(&self) -> &ApplicationHeadV0 {
        &self.head
    }
    pub const fn p_digest(&self) -> [u8; 32] {
        self.p_digest
    }
    pub const fn commit_sequence(&self) -> u64 {
        self.commit_sequence
    }
    pub fn belongs_to_application(&self, app: &DurableNativeApplicationV0) -> bool {
        if !Arc::ptr_eq(&self.owner, &app.owner_affinity) {
            return false;
        }
        (|| -> Result<bool> {
            let _guard = app.lock_operation()?;
            let connection = open_immutable_connection_v0(&app.path)?;
            verify_schema_v0(&connection)?;
            let tx = connection.unchecked_transaction()?;
            let metadata = load_metadata_v0(&tx, &app.config)?;
            validate_metadata_v0(&tx, &app.config, &metadata)?;
            let row = load_p(&tx, self.head.block_id().as_bytes())?
                .context("committed epoch receipt P missing")?;
            validate_p(&tx, &app.config, &row)?;
            Ok(metadata.head == self.head
                && row.target_head()? == self.head
                && row.status == 1
                && row.p_digest == self.p_digest
                && row.commit_sequence == Some(self.commit_sequence))
        })()
        .unwrap_or(false)
    }
}

impl DurableNativeApplicationV0 {
    pub fn commit_epoch_finality_bytes_v1(
        &self,
        prepared: &PreparedNativeEpochExecutionV1,
        proof_bytes: &[u8],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<CommittedNativeEpochExecutionV1> {
        ensure!(
            Arc::ptr_eq(&prepared.owner, &self.owner_affinity),
            "epoch commit foreign owner"
        );
        let ids = decode_lineage(&prepared.row.lineage)?;
        let binding = *ids.last().context("epoch commit missing edge")?;
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        if descendant_finality::binding(&connection, &prepared.row)?.is_some() {
            ensure!(
                has_later_descendant_finality_schema(schema_version(&connection)?),
                "later descendant commit requires schema10 ordinary finality"
            );
        }
        let legacy_edge = load_edges(&connection, &self.config)?
            .into_iter()
            .find(|edge| edge.binding == binding)
            .map(|_| binding);
        let later_checkpoint = if legacy_edge.is_none() {
            ensure!(
                has_later_application_finality_schema(schema_version(&connection)?),
                "later descendant commit requires schema9 application finality"
            );
            Some(connection.query_row(
                "SELECT checkpoint_block FROM native_later_epoch_edge_v1 WHERE successor_binding=?1",
                [binding.as_slice()],
                |row| col32(row, "checkpoint_block"),
            )?)
        } else {
            None
        };
        drop(connection);
        let edge = legacy_edge
            .map(|binding| self.recover_epoch_application_edge_v1(binding))
            .transpose()?;
        let later_edge = if let Some(checkpoint) = later_checkpoint {
            let requirements =
                self.inspect_later_epoch_application_edge_requirements_v1(checkpoint)?;
            ensure!(
                requirements.successor_binding() == binding,
                "later first-new lineage binding"
            );
            Some(self.recover_later_epoch_application_edge_v1(&requirements)?)
        } else {
            None
        };
        let later_context = later_edge
            .as_ref()
            .map(|edge| self.open_later_epoch_execution_context_v1(edge))
            .transpose()?;
        self.verify_epoch_application_finality_v1(
            prepared,
            proof_bytes,
            budget,
            edge.as_ref(),
            later_context.as_ref(),
        )?;
        self.commit_epoch_p(
            prepared,
            None,
            later_edge
                .as_ref()
                .filter(|_| prepared.row.artifact_kind == 1),
            Some(proof_bytes),
            None,
        )
    }

    // Keep decoded proof temporaries off the authority-recovery stack: both
    // paths perform strict validation, but need not reserve their largest
    // frames at the same time in unoptimized builds.
    #[inline(never)]
    fn verify_epoch_application_finality_v1(
        &self,
        prepared: &PreparedNativeEpochExecutionV1,
        proof_bytes: &[u8],
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
        edge: Option<&crate::AuthenticatedEpochApplicationEdgeV1>,
        later_context: Option<&LaterEpochExecutionContextV1>,
    ) -> Result<()> {
        let _guard = self.lock_operation()?;
        let connection = open_immutable_connection_v0(&self.path)?;
        connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
        verify_schema_v0(&connection)?;
        let header = prepared.header()?;
        ensure!(
            header.block_kind() != BlockKind::EpochCheckpoint,
            "later-epoch checkpoint finality bridge required"
        );
        let expected = trnm_consensus_crypto::FinalityExpectationV0 {
            block_id: header.id(),
            height: header.height(),
            state_root: header.state_root(),
            receipts_root: header.receipts_root(),
            evidence_root: header.evidence_root(),
            parent_id: trnm_consensus_types::BlockId::new(prepared.row.consensus_parent_block),
            parent_height: trnm_consensus_types::Height::new(prepared.row.consensus_parent_height),
            parent_timestamp_ms: if let Some(context) =
                later_context.filter(|_| prepared.row.artifact_kind == 1)
            {
                context.consensus_parent_v1().timestamp_ms()
            } else if prepared.row.artifact_kind == 1 {
                edge.as_ref()
                    .context("legacy epoch edge missing")?
                    .consensus_parent()
                    .timestamp_ms()
            } else {
                let parent = load_p(&connection, prepared.row.parent.block_id().as_bytes())?
                    .context("finality parent P missing")?;
                decode_header(&parent.header)?.timestamp_ms()
            },
        };
        let mut prefix = lineage_resolver::resolve(
            &connection,
            &self.config,
            &decode_lineage(&prepared.row.lineage)?,
        )?;
        let activation = prefix
            .entries
            .pop()
            .context("finality epoch prefix empty")?;
        let final_header = verify_retained_epoch_runtime_finality_v1(
            activation.audit.activation,
            proof_bytes,
            expected,
            budget,
        )?;
        ensure!(
            final_header == header,
            "strict finality differs from complete retained header"
        );
        connection.execute_batch("ROLLBACK")?;
        #[cfg(unix)]
        self.confirm_namespace_identity_v1()?;
        Ok(())
    }

    fn commit_epoch_p(
        &self,
        prepared: &PreparedNativeEpochExecutionV1,
        later: Option<&crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1>,
        later_application: Option<&LaterEpochApplicationEdgeV1>,
        application_proof: Option<&[u8]>,
        pre_handoff: Option<&pre_handoff::EvidenceV1>,
    ) -> Result<CommittedNativeEpochExecutionV1> {
        let _guard = self.lock_operation()?;
        let mut connection = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let metadata = load_metadata_v0(&connection, &self.config)?;
        let inventory = validate_metadata_v0(&connection, &self.config, &metadata)?;
        let p = load_p(&connection, &prepared.row.block_id)?.context("epoch commit P missing")?;
        ensure!(
            p.p_digest == prepared.row.p_digest
                && p.artifact == prepared.row.artifact
                && p.header == prepared.row.header,
            "epoch commit P substituted"
        );
        validate_p(&connection, &self.config, &p)?;
        // Recheck the proof-retention requirement at the locked write/retry
        // boundary, including ordinary descendants that do not consume an
        // edge or write a first-new proof record themselves.
        let lineage = decode_lineage(&p.lineage)?;
        let binding = lineage.last().context("epoch commit lineage missing")?;
        let legacy: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM native_epoch_edge_v1 WHERE binding=?1)",
            [binding.as_slice()],
            |row| row.get(0),
        )?;
        ensure!(
            legacy || has_later_application_finality_schema(schema_version(&connection)?),
            "later descendant commit requires schema9 application finality"
        );
        let ordinary_binding = descendant_finality::binding(&connection, &p)?;
        if ordinary_binding.is_some() {
            ensure!(
                has_later_descendant_finality_schema(schema_version(&connection)?),
                "later descendant commit requires schema10 ordinary finality"
            );
            descendant_finality::check_proof_bounds(
                application_proof.context("later descendant finality proof missing")?,
            )?;
        }
        let prospective_sequence = p.commit_sequence.unwrap_or(
            metadata
                .durable_sequence
                .checked_add(1)
                .context("epoch commit sequence exhausted")?,
        );
        if let Some(evidence) = pre_handoff {
            ensure!(
                later.is_none() && later_application.is_none() && application_proof.is_none(),
                "pre-handoff commit cannot carry a successor authority"
            );
            ensure!(
                schema_version(&connection)? == PRE_HANDOFF_SCHEMA_VERSION,
                "pre-handoff commit requires explicit schema13"
            );
            pre_handoff::verify(
                &connection,
                &self.config,
                &p,
                evidence,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )?;
            pre_handoff::check_capacity(&connection, &p)?;
        }
        let later_facts = if let Some(evidence) = later {
            ensure!(
                has_later_schema(schema_version(&connection)?),
                "explicit schema8 later finality revision required"
            );
            let facts = derive_later_successor_facts(
                &connection,
                &self.config,
                &p,
                prospective_sequence,
                evidence,
            )?;
            if p.status == 0 {
                let count: u64 = connection.query_row(
                    "SELECT COUNT(*) FROM native_later_epoch_finality_v1",
                    [],
                    |row| row.get(0),
                )?;
                ensure!(
                    count < MAX_EDGES as u64,
                    "later checkpoint ledger capacity unavailable"
                );
            }
            Some(facts)
        } else {
            None
        };
        if later_application.is_some() {
            ensure!(
                has_later_application_finality_schema(schema_version(&connection)?),
                "schema9 application finality ledger required"
            );
            let proof = application_proof.context("later application finality proof missing")?;
            ensure!(
                !proof.is_empty() && proof.len() <= MAX_EPOCH_EVIDENCE_BYTES_V1,
                "later application finality proof budget"
            );
        }
        if let Some(evidence) = later {
            let facts = later_facts
                .as_ref()
                .context("later successor facts missing")?;
            ensure!(
                facts.proof_context_digest == evidence.context_digest
                    && facts.predecessor_edge == evidence.predecessor_edge,
                "later successor facts differ from proof evidence"
            );
        } else if pre_handoff.is_none() {
            ensure!(
                decode_header(&p.header)?.block_kind() != BlockKind::EpochCheckpoint,
                "later-epoch checkpoint finality bridge required"
            );
        }
        if p.status == 1 {
            let sequence = p
                .commit_sequence
                .context("committed epoch sequence missing")?;
            if let Some(evidence) = pre_handoff {
                ensure!(
                    metadata.head == p.target_head()?,
                    "pre-handoff retry is no longer current"
                );
                pre_handoff::check_retry(&connection, &self.config, &p, sequence, evidence)?;
            }
            if let Some(evidence) = later {
                ensure!(
                    metadata.head == p.target_head()?,
                    "later checkpoint retry is no longer current"
                );
                let digest =
                    later_record_digest(&self.config, &p.block_id, &p.p_digest, sequence, evidence);
                let retained: [u8; 32] = connection.query_row(
                    "SELECT record_digest FROM native_later_epoch_finality_v1 WHERE checkpoint_block=?1",
                    [p.block_id.as_slice()], |row| col32(row, "record_digest"),
                )?;
                ensure!(digest == retained, "later checkpoint conflicting retry");
                let facts = later_facts
                    .as_ref()
                    .context("later successor facts missing")?;
                let retained_edge: [u8; 32] = connection.query_row(
                    "SELECT record_digest FROM native_later_epoch_edge_v1 WHERE checkpoint_block=?1",
                    [p.block_id.as_slice()],
                    |row| col32(row, "record_digest"),
                )?;
                ensure!(
                    facts.record_digest == retained_edge,
                    "later successor edge conflicting retry"
                );
            }
            if let Some(later_edge) = later_application {
                let proof =
                    application_proof.context("later application finality proof missing")?;
                let proof_digest = sha256_v0(proof);
                let retained: (Vec<u8>, Vec<u8>, Vec<u8>) = connection.query_row(
                    "SELECT proof,proof_digest,record_digest
                     FROM native_later_epoch_application_finality_v1 WHERE block_id=?1",
                    [p.block_id.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                let retained_proof_digest: [u8; 32] = retained
                    .1
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("retained application proof digest width"))?;
                let retained_record_digest: [u8; 32] = retained
                    .2
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("retained application record digest width"))?;
                ensure!(
                    retained.0 == proof
                        && retained_proof_digest == proof_digest
                        && retained_record_digest
                            == later_application_finality_record_digest(
                                &self.config,
                                &p.block_id,
                                &p.p_digest,
                                sequence,
                                &later_edge.successor_binding,
                                &proof_digest,
                            ),
                    "later application conflicting retry"
                );
            }
            if let Some(binding) = ordinary_binding {
                descendant_finality::check_retry(
                    &connection,
                    &self.config,
                    &p,
                    sequence,
                    binding,
                    application_proof.context("later descendant finality proof missing")?,
                )?;
            }
            drop(connection);
            sync_store_commit_boundary_v0(&self.path)?;
            fresh_validate_v0(&self.path, &self.config)?;
            let connection = open_immutable_connection_v0(&self.path)?;
            let read = load_p(&connection, &p.block_id)?.context("retried committed P missing")?;
            ensure!(
                read.status == 1
                    && read.p_digest == p.p_digest
                    && read.commit_sequence == Some(sequence)
                    && read.commit_id == p.commit_id,
                "retried committed P changed"
            );
            return Ok(CommittedNativeEpochExecutionV1 {
                owner: Arc::clone(&self.owner_affinity),
                head: p.target_head()?,
                p_digest: p.p_digest,
                commit_sequence: sequence,
            });
        }
        ensure!(
            metadata.head == p.parent,
            "epoch commit predecessor not current head"
        );
        let sequence = prospective_sequence;
        let head = p.target_head()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if ordinary_binding.is_some() {
            descendant_finality::check_capacity(
                &tx,
                application_proof.context("later descendant finality proof missing")?,
            )?;
        }
        let changed=tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=?,head_height=?,head_block_id=?,head_state_root=?,head_commit_id=?,authenticated_snapshot=?,authenticated_snapshot_digest=?,replay_command_ids=?,replay_signer_nonces=? WHERE singleton=1 AND durable_sequence=? AND head_height=? AND head_block_id=? AND head_state_root=? AND head_commit_id=?",
            params![sequence.to_be_bytes().as_slice(),head.height().get().to_be_bytes().as_slice(),head.block_id().as_bytes().as_slice(),head.state_root().as_bytes().as_slice(),head.commit_id().as_bytes().as_slice(),
                &p.snapshot,p.snapshot_digest.as_slice(),&p.commands,&p.nonces,metadata.durable_sequence.to_be_bytes().as_slice(),metadata.head.height().get().to_be_bytes().as_slice(),metadata.head.block_id().as_bytes().as_slice(),
                metadata.head.state_root().as_bytes().as_slice(),metadata.head.commit_id().as_bytes().as_slice()])?;
        ensure!(changed == 1, "epoch commit metadata CAS failed");
        ensure!(tx.execute("UPDATE native_durable_execution_p_v1 SET status=1,commit_sequence=?,commit_id=? WHERE block_id=? AND status=0 AND p_digest=?",
            params![sequence.to_be_bytes().as_slice(),head.commit_id().as_bytes().as_slice(),p.block_id.as_slice(),p.p_digest.as_slice()])?==1,"epoch commit P CAS failed");
        if p.artifact_kind == 1 {
            let ids = decode_lineage(&p.lineage)?;
            let binding = ids.last().context("epoch commit edge missing")?;
            if let Some(later_edge) = later_application {
                ensure!(
                    later_edge.successor_binding == *binding
                        && later_edge.checkpoint_block == *p.parent.block_id().as_bytes()
                        && later_edge.checkpoint_p_digest
                            == p.parent_p_digest
                                .context("later successor parent P digest missing")?,
                    "later successor commit edge binding"
                );
                ensure!(tx.execute("UPDATE native_later_epoch_edge_v1 SET phase=1,consumed_block=?,consumed_sequence=? WHERE successor_binding=? AND phase=0 AND checkpoint_block=? AND checkpoint_p_digest=? AND checkpoint_commit_sequence=?",
                    params![p.block_id.as_slice(),sequence.to_be_bytes().as_slice(),binding.as_slice(),p.parent.block_id().as_bytes().as_slice(),later_edge.checkpoint_p_digest.as_slice(),later_edge.checkpoint_commit_sequence.to_be_bytes().as_slice()])?==1,
                    "later successor edge already consumed/conflicting");
            } else {
                ensure!(tx.execute("UPDATE native_epoch_edge_v1 SET phase=1,consumed_block=?,consumed_sequence=? WHERE binding=? AND phase=0 AND checkpoint_block=? AND checkpoint_root=?",
                    params![p.block_id.as_slice(),sequence.to_be_bytes().as_slice(),binding.as_slice(),p.parent.block_id().as_bytes().as_slice(),p.parent.state_root().as_bytes().as_slice()])?==1,
                    "epoch commit edge already consumed/conflicting");
            }
        }
        let context = context_digest(
            self.config.store_id,
            &head,
            sequence,
            &p.target_set,
            &p.target_parameters,
            &p.lineage,
        );
        tx.execute("INSERT INTO native_application_epoch_context_v1 VALUES (1,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET head_block=excluded.head_block,head_root=excluded.head_root,head_commit_id=excluded.head_commit_id,head_height=excluded.head_height,head_commit_sequence=excluded.head_commit_sequence,active_set=excluded.active_set,active_parameters=excluded.active_parameters,edge_lineage=excluded.edge_lineage,context_digest=excluded.context_digest",
            params![self.config.store_id.as_slice(),head.block_id().as_bytes().as_slice(),head.state_root().as_bytes().as_slice(),head.commit_id().as_bytes().as_slice(),head.height().get().to_be_bytes().as_slice(),
                sequence.to_be_bytes().as_slice(),&p.target_set,&p.target_parameters,&p.lineage,context.as_slice()])?;
        if let Some(evidence) = pre_handoff {
            pre_handoff::insert(&tx, &self.config, &p, sequence, evidence)?;
        }
        if let Some(evidence) = later {
            let facts = later_facts
                .as_ref()
                .context("later successor facts missing")?;
            insert_later_records_v1(&tx, &self.config, &p, sequence, evidence, facts)?;
        }
        if let Some(later_edge) = later_application {
            let proof = application_proof.context("later application finality proof missing")?;
            let proof_digest = sha256_v0(proof);
            let record_digest = later_application_finality_record_digest(
                &self.config,
                &p.block_id,
                &p.p_digest,
                sequence,
                &later_edge.successor_binding,
                &proof_digest,
            );
            tx.execute(
                "INSERT INTO native_later_epoch_application_finality_v1 VALUES (?,?,?,?,?,?,?)",
                params![
                    p.block_id.as_slice(),
                    p.p_digest.as_slice(),
                    sequence.to_be_bytes().as_slice(),
                    later_edge.successor_binding.as_slice(),
                    proof,
                    proof_digest.as_slice(),
                    record_digest.as_slice(),
                ],
            )?;
        }
        if let Some(binding) = ordinary_binding {
            descendant_finality::insert(
                &tx,
                &self.config,
                &p,
                sequence,
                binding,
                application_proof.context("later descendant finality proof missing")?,
            )?;
        }
        let pruned = prepared_blocks_not_descending_from_v0(&inventory, p.block_id);
        for block in pruned {
            tx.execute(
                "DELETE FROM native_durable_execution_p_v1 WHERE block_id=? AND status=0",
                params![block.as_slice()],
            )?;
            tx.execute(
                "DELETE FROM native_durable_execution_p_v0 WHERE block_id=? AND status=?",
                params![block.as_slice(), P_STATUS_PREPARED.to_be_bytes().as_slice()],
            )?;
        }
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0(if pre_handoff.is_some() {
            "later_pre_handoff_before_commit"
        } else if later_application.is_some() {
            "later_application_before_commit"
        } else if later.is_some() {
            "later_epoch_before_commit"
        } else if ordinary_binding.is_some() {
            "later_descendant_before_commit"
        } else {
            "epoch_before_commit"
        });
        tx.commit()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0(if pre_handoff.is_some() {
            "later_pre_handoff_after_commit"
        } else if later_application.is_some() {
            "later_application_after_commit"
        } else if later.is_some() {
            "later_epoch_after_commit"
        } else if ordinary_binding.is_some() {
            "later_descendant_after_commit"
        } else {
            "epoch_after_commit"
        });
        drop(connection);
        sync_store_commit_boundary_v0(&self.path)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0(if pre_handoff.is_some() {
            "later_pre_handoff_after_fsync"
        } else if later_application.is_some() {
            "later_application_after_fsync"
        } else if later.is_some() {
            "later_epoch_after_fsync"
        } else if ordinary_binding.is_some() {
            "later_descendant_after_fsync"
        } else {
            "epoch_after_fsync"
        });
        let fresh = fresh_validate_v0(&self.path, &self.config)?;
        ensure!(
            fresh.head == head && fresh.durable_sequence == sequence,
            "epoch commit fresh metadata mismatch"
        );
        let connection = open_immutable_connection_v0(&self.path)?;
        let read = load_p(&connection, &p.block_id)?.context("epoch committed P missing")?;
        ensure!(
            read.status == 1
                && read.p_digest == p.p_digest
                && read.commit_sequence == Some(sequence)
                && read.target_head()? == head,
            "epoch commit fresh P mismatch"
        );
        Ok(CommittedNativeEpochExecutionV1 {
            owner: Arc::clone(&self.owner_affinity),
            head,
            p_digest: p.p_digest,
            commit_sequence: sequence,
        })
    }
}

fn insert_later_records_v1(
    tx: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    sequence: u64,
    evidence: &crate::later_epoch_checkpoint_bridge::LaterEpochFinalityPreimagesV1,
    facts: &LaterSuccessorFactsV1,
) -> Result<()> {
    let digest = later_record_digest(config, &p.block_id, &p.p_digest, sequence, evidence);
    tx.execute(
        "INSERT INTO native_later_epoch_finality_v1 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            p.block_id.as_slice(),
            p.p_digest.as_slice(),
            sequence.to_be_bytes().as_slice(),
            evidence.context_digest.as_slice(),
            evidence.predecessor_edge.as_slice(),
            &evidence.checkpoint_parent_header,
            &evidence.checkpoint_header,
            &evidence.checkpoint_finality,
            &evidence.anchor_kernel,
            &evidence.next_epoch_commitment,
            &evidence.new_validator_set,
            &evidence.new_parameters,
            digest.as_slice(),
        ],
    )?;
    tx.execute(
        "INSERT INTO native_later_epoch_edge_v1 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            facts.successor_binding.as_slice(),
            facts.predecessor_edge.as_slice(),
            facts.checkpoint_block.as_slice(),
            facts.checkpoint_p_digest.as_slice(),
            facts.checkpoint_commit_sequence.to_be_bytes().as_slice(),
            facts.checkpoint_height.to_be_bytes().as_slice(),
            facts.checkpoint_root.as_slice(),
            facts.checkpoint_commit_id.as_slice(),
            facts.terminal_height.to_be_bytes().as_slice(),
            facts.terminal_block.as_slice(),
            facts.first_height.to_be_bytes().as_slice(),
            facts.proof_context_digest.as_slice(),
            facts.successor_context_digest.as_slice(),
            facts.authority_digest.as_slice(),
            0_i64,
            Option::<&[u8]>::None,
            Option::<&[u8]>::None,
            facts.record_digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn context_digest(
    store: [u8; 32],
    head: &ApplicationHeadV0,
    sequence: u64,
    set: &[u8],
    parameters: &[u8],
    lineage: &[u8],
) -> [u8; 32] {
    hash_domain(
        "trnm.native-application.epoch-context.v1",
        &[
            &store,
            &head.height().get().to_be_bytes(),
            head.block_id().as_bytes(),
            head.state_root().as_bytes(),
            head.commit_id().as_bytes(),
            &sequence.to_be_bytes(),
            &sha256_v0(set),
            &sha256_v0(parameters),
            &sha256_v0(lineage),
        ],
    )
}

fn validate_context(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
) -> Result<()> {
    let lengths:[i64;3]=connection.query_row("SELECT length(active_set),length(active_parameters),length(edge_lineage) FROM native_application_epoch_context_v1 WHERE singleton=1",[],|r|Ok([r.get(0)?,r.get(1)?,r.get(2)?]))?;
    ensure!(
        lengths
            .iter()
            .zip([MAX_SET_BYTES, MAX_PARAMETERS_BYTES, 4 + 32 * MAX_EDGES])
            .all(|(&n, cap)| n >= 0 && n as usize <= cap),
        "epoch context resource budget"
    );
    let r = connection.query_row(
        "SELECT * FROM native_application_epoch_context_v1 WHERE singleton=1",
        [],
        |r| {
            Ok((
                col32(r, "store_id")?,
                col32(r, "head_block")?,
                col32(r, "head_root")?,
                col32(r, "head_commit_id")?,
                col64(r, "head_height")?,
                col64(r, "head_commit_sequence")?,
                r.get::<_, Vec<u8>>("active_set")?,
                r.get::<_, Vec<u8>>("active_parameters")?,
                r.get::<_, Vec<u8>>("edge_lineage")?,
                col32(r, "context_digest")?,
            ))
        },
    )?;
    let head = p.target_head()?;
    ensure!(
        r.0 == config.store_id
            && &r.1 == head.block_id().as_bytes()
            && &r.2 == head.state_root().as_bytes()
            && &r.3 == head.commit_id().as_bytes()
            && r.4 == head.height().get()
            && Some(r.5) == p.commit_sequence
            && r.6 == p.target_set
            && r.7 == p.target_parameters
            && r.8 == p.lineage
            && r.9 == context_digest(config.store_id, &head, r.5, &r.6, &r.7, &r.8),
        "committed epoch context mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod descendant_kind_tests {
    use super::*;
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusParametersHash, Epoch, EvidenceRoot, GenesisHash, Height,
        NextEpochCommitmentHash, PayloadDigest, ProtocolVersion, ReceiptsRoot, StateRoot,
        ValidatorId, ValidatorSetId, View,
    };

    fn header(kind: BlockKind, commitment: Option<NextEpochCommitmentHash>) -> BlockHeader {
        BlockHeader::new(
            GenesisHash::new([1; 32]),
            ChainId::new("epoch-descendant-kind-test").unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            View::new(1),
            Height::new(1),
            kind,
            BlockId::new([2; 32]),
            ValidatorId::from_bytes(b"validator-0").unwrap(),
            ValidatorSetId::new([3; 32]),
            ConsensusParametersHash::new([4; 32]),
            PayloadDigest::new([5; 32]),
            StateRoot::new([6; 32]),
            ReceiptsRoot::new([7; 32]),
            EvidenceRoot::new([8; 32]),
            1,
            commitment,
        )
        .unwrap()
    }

    #[test]
    fn descendant_kind_requires_a_dedicated_checkpoint_bridge() {
        let commitment = Some(NextEpochCommitmentHash::new([9; 32]));
        assert!(validate_epoch_descendant_kind(&header(BlockKind::Regular, None)).is_ok());
        assert!(
            validate_epoch_descendant_kind(&header(BlockKind::EpochCheckpoint, commitment)).is_ok()
        );
        assert!(
            validate_epoch_descendant_kind(&header(BlockKind::EpochSeal1, commitment)).is_err()
        );
        assert!(validate_epoch_descendant_kind(&header(BlockKind::EpochHandoff, None)).is_err());
    }
}
