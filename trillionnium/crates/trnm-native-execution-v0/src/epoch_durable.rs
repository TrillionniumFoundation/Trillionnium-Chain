//! Explicit schema-4 bridge. No schema migration is performed by ordinary open.
//! Frozen v0 rows remain immutable; sparse-history executions use a separate P.
use super::*;
use crate::epoch_recovery::{EpochRecoveryEvidenceV1, MAX_EPOCH_EVIDENCE_BYTES_V1};
use anyhow::Result;
use trnm_consensus_types::BlockKind;
use trnm_native_application::{NativeEpochBlockExecutionRequestV1, NativeExecutedEpochBlockV1};

pub(super) const SCHEMA_VERSION: u64 = 4;
const MAX_P_ROWS: usize = 128;
const MAX_PREPARED_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
const MAX_REPLAY_BYTES: usize = 16 * 1024 * 1024;
const MAX_LIFECYCLE_BYTES: usize = 1024 * 1024;
const MAX_EDGES: usize = 32;
const MAX_HEADER_BYTES: usize = 4096;
const MAX_SET_BYTES: usize = 1024 * 1024;
const MAX_PARAMETERS_BYTES: usize = 4096;

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
}

impl FinalizedNativeEpochApplicationReadV1 {
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

fn local_error(_: impl std::fmt::Display) -> NativeApplicationExecutionErrorV0 {
    error(
        NativeApplicationExecutionErrorCodeV0::CorruptStore,
        "epoch_bridge.audit",
    )
}

pub(super) fn schema_version(connection: &Connection) -> DurableResult<u64> {
    let value: Vec<u8> = connection
        .query_row(
            "SELECT schema_version FROM native_application_metadata_v0 WHERE singleton=1",
            [],
            |r| r.get(0),
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
        let edge =
            self.recover_epoch_application_edge_v1(*ids.last().context("parent lineage missing")?)?;
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
            edge.new_validator_set(),
            edge.new_validator_set().genesis_hash(),
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
        if schema_version(&connection)? == SCHEMA_VERSION {
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
}

fn col32(row: &rusqlite::Row<'_>, name: &str) -> rusqlite::Result<[u8; 32]> {
    row.get::<_, Vec<u8>>(name)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}
fn col64(row: &rusqlite::Row<'_>, name: &str) -> rusqlite::Result<u64> {
    Ok(u64::from_be_bytes(
        row.get::<_, Vec<u8>>(name)?
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    ))
}
fn opt32(row: &rusqlite::Row<'_>, name: &str) -> rusqlite::Result<Option<[u8; 32]>> {
    row.get::<_, Option<Vec<u8>>>(name)?
        .map(|v| v.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
        .transpose()
}
fn opt64(row: &rusqlite::Row<'_>, name: &str) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<Vec<u8>>>(name)?
        .map(|v| {
            Ok(u64::from_be_bytes(
                v.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
            ))
        })
        .transpose()
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
            schema_version(&connection)? == SCHEMA_VERSION,
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
            schema_version(&connection)? == SCHEMA_VERSION,
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
            schema_version(&connection)? == SCHEMA_VERSION,
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
    audited_lineage_with_seen(connection, config, ids, &mut BTreeSet::new())
}

/// Audit an ordered edge lineage while carrying the active recursion set.
///
/// A later checkpoint P is itself stored in the schema-4 table and its
/// lineage points at the already-consumed edge(s).  Reusing `validate_p`
/// therefore makes the audit recursive.  The active set is required so a
/// forged cycle (A -> B -> A) cannot recurse until stack exhaustion or be
/// mistaken for a valid second epoch.
fn audited_lineage_with_seen(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    ids: &[[u8; 32]],
    seen: &mut BTreeSet<[u8; 32]>,
) -> Result<Vec<([u8; 32], crate::epoch_recovery::AuditedEpochEvidenceV1)>> {
    let edges = load_edges(connection, config)?;
    let mut old_set = config.validator_set.clone();
    let mut parameters = config.parameters;
    let mut previous_height = 0;
    let mut result = Vec::new();
    for id in ids {
        ensure!(seen.insert(*id), "epoch lineage cycle");
        let edge = edges
            .iter()
            .find(|e| &e.binding == id)
            .context("retained epoch evidence missing")?;
        ensure!(
            edge.first_height > previous_height,
            "epoch lineage height order"
        );
        if let Some(checkpoint) =
            load_p_by_block_v0(connection, *edge.checkpoint.block_id().as_bytes())?
        {
            validate_p_v0(config, &checkpoint)?;
            validate_target_snapshot_v0(config, &checkpoint)?;
            ensure!(
                checkpoint.status == P_STATUS_COMMITTED
                    && checkpoint.p_digest == edge.checkpoint_p_digest
                    && checkpoint.commit_sequence == Some(edge.checkpoint_sequence)
                    && checkpoint.commit_id == Some(*edge.checkpoint.commit_id().as_bytes())
                    && checkpoint.target_height == edge.checkpoint.height().get()
                    && checkpoint.artifact == edge.evidence.checkpoint_artifact,
                "retained checkpoint identity mismatch"
            );
        } else {
            // A later epoch's checkpoint is a committed schema-4 ordinary P
            // whose lineage names the already authenticated edge(s).  It is
            // intentionally not accepted by the legacy v0 loader above.
            let checkpoint = load_p(connection, edge.checkpoint.block_id().as_bytes())?
                .context("retained checkpoint P missing")?;
            ensure!(
                checkpoint.status == P_STATUS_COMMITTED as i64
                    && checkpoint.artifact_kind == 0
                    && checkpoint.target_head()? == edge.checkpoint
                    && checkpoint.p_digest == edge.checkpoint_p_digest
                    && checkpoint.commit_sequence == Some(edge.checkpoint_sequence)
                    && checkpoint.commit_id == Some(*edge.checkpoint.commit_id().as_bytes())
                    && checkpoint.artifact == edge.evidence.checkpoint_artifact,
                "retained later-epoch checkpoint identity mismatch"
            );
            let checkpoint_header = decode_header(&checkpoint.header)?;
            ensure!(
                checkpoint_header.block_kind() == BlockKind::EpochCheckpoint
                    && checkpoint_header.next_epoch_commitment_hash().is_some(),
                "retained later-epoch checkpoint kind/commitment"
            );
            // This validates the complete v1 artifact, snapshot, replay and
            // parent binding.  Its recursive lineage audit reuses `seen`.
            validate_p_with_seen(connection, config, &checkpoint, seen)?;
        }
        let mut budget = trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0();
        let audit = edge
            .evidence
            .audit_strict(&old_set, &parameters, &mut budget)?;
        let coords = audit.coordinates(*id)?;
        ensure!(
            coords.checkpoint_version == edge.checkpoint.height().get()
                && &coords.checkpoint_root == edge.checkpoint.state_root().as_bytes()
                && coords.first_version == edge.first_height
                && coords.terminal_version == edge.terminal_height
                && audit
                    .activation
                    .authorization_kernel()
                    .terminal_old_header()
                    .id()
                    .as_bytes()
                    == &edge.terminal_block,
            "retained edge coordinate mismatch"
        );
        ensure!(
            (edge.phase == 0 && edge.consumed.is_none() && edge.consumed_sequence.is_none())
                || (edge.phase == 1 && edge.consumed.is_some() && edge.consumed_sequence.is_some()),
            "edge phase malformed"
        );
        if edge.phase == 1 {
            let consumer = load_p(
                connection,
                &edge.consumed.context("consumed edge target missing")?,
            )?
            .context("consumed edge P missing")?;
            ensure!(
                consumer.status == 1
                    && consumer.artifact_kind == 1
                    && consumer.commit_sequence == edge.consumed_sequence
                    && decode_lineage(&consumer.lineage)?.last() == Some(id),
                "consumed edge P mismatch"
            );
        }
        old_set = audit.activation.new_validator_set().clone();
        parameters = *audit.activation.new_consensus_parameters();
        previous_height = edge.first_height;
        result.push((*id, audit));
        seen.remove(id);
    }
    Ok(result)
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
    validate_p_with_seen(connection, config, p, &mut BTreeSet::new())
}

fn validate_p_with_seen(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
    p: &StoredEpochPV1,
    seen: &mut BTreeSet<[u8; 32]>,
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
    ensure!(
        header.id().as_bytes() == &p.block_id
            && header.height().get() == p.target_height
            && header.parent_id().as_bytes() == &p.consensus_parent_block
            && header.chain_id().as_str() == config.chain_id
            && header.genesis_hash().as_bytes() == &config.genesis_hash,
        "epoch P header identity"
    );
    let lineage = decode_lineage(&p.lineage)?;
    let edges = audited_lineage_with_seen(connection, config, &lineage, seen)?;
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
            let edges = load_edges(connection, config)?;
            let edge = edges
                .iter()
                .find(|e| Some(&e.binding) == lineage.last())
                .context("committed edge missing")?;
            ensure!(
                edge.phase == 1
                    && edge.consumed == Some(p.block_id)
                    && edge.consumed_sequence == p.commit_sequence,
                "committed epoch edge phase mismatch"
            );
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
    let store = InMemoryNativeExecutionStoreV0::decode_recovered_epoch_snapshot_v1(
        config.chain_id.clone(),
        config.signers.clone(),
        *parameters,
        commands,
        nonces,
        &p.snapshot,
        &edges,
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

pub(super) fn inventory(
    connection: &Connection,
    config: &NativeApplicationConfigV0,
) -> DurableResult<Vec<ValidatedPInventoryEntryV0>> {
    (|| -> Result<_> {
        // Even an installed edge not yet referenced by a P must retain valid evidence.
        for edge in load_edges(connection, config)? {
            audited_lineage(connection, config, &[edge.binding])?;
        }
        let values = all_p(connection)?;
        let mut rows = Vec::new();
        for p in values {
            validate_p(connection, config, &p)?;
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
    (|| -> Result<_> {
        if let Some(p) = load_p(connection, metadata.head.block_id().as_bytes())? {
            ensure!(
                p.status == 1
                    && p.target_head()? == metadata.head
                    && p.snapshot == metadata.snapshot
                    && p.snapshot_digest == metadata.snapshot_digest,
                "epoch metadata differs from committed P"
            );
            let store = validate_p(connection, config, &p)?;
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
            schema_version(&connection)? == SCHEMA_VERSION,
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
        let edges = bindings
            .iter()
            .map(|id| self.recover_epoch_application_edge_v1(*id))
            .collect::<Result<Vec<_>>>()?;
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
        let active = edges.last().context("prepared parent has no edge")?;
        let execution = execute_complete_native_block_v0(
            &target,
            active.new_validator_set(),
            active.new_validator_set().genesis_hash(),
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
        let snapshot =
            target.encode_epoch_authenticated_snapshot_v1(&edges.iter().collect::<Vec<_>>())?;
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
            schema_version(&connection)? == SCHEMA_VERSION,
            "epoch schema unavailable"
        );
        let metadata = load_metadata_v0(&connection, &self.config)?;
        validate_metadata_v0(&connection, &self.config, &metadata)?;
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
        let connection = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&connection)?;
        let prior = load_p(&connection, &block)?.context("epoch P missing")?;
        drop(connection);
        for id in decode_lineage(&prior.lineage)? {
            let _edge = self.recover_epoch_application_edge_v1(id)?;
        }
        let _guard = self.lock_operation()?;
        fresh_validate_v0(&self.path, &self.config)?;
        let connection = open_immutable_connection_v0(&self.path)?;
        let row = load_p(&connection, &block)?.context("epoch P missing")?;
        validate_p(&connection, &self.config, &row)?;
        ensure!(
            row.p_digest == prior.p_digest,
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
        let edge = self
            .recover_epoch_application_edge_v1(*ids.last().context("epoch commit missing edge")?)?;
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
            parent_timestamp_ms: if prepared.row.artifact_kind == 1 {
                edge.consensus_parent().timestamp_ms()
            } else {
                let connection = open_immutable_connection_v0(&self.path)?;
                let parent = load_p(&connection, prepared.row.parent.block_id().as_bytes())?
                    .context("finality parent P missing")?;
                decode_header(&parent.header)?.timestamp_ms()
            },
        };
        let final_header = if prepared.row.artifact_kind == 1 {
            let verified = trnm_consensus_crypto::decode_verify_epoch_first_finality_strict_v1(
                edge.recovery_evidence().proof_preimages(),
                proof_bytes,
                edge.old_validator_set(),
                edge.old_parameters(),
                expected,
                budget,
            )
            .map_err(|e| anyhow::anyhow!("first-new strict finality: {e}"))?;
            ensure!(
                verified.checkpoint_header().id().as_bytes()
                    == edge.application_parent().block_id().as_bytes(),
                "epoch finality checkpoint substitution"
            );
            verified.proof().finalized_block().header().clone()
        } else {
            trnm_consensus_crypto::decode_verify_finality_proof_strict_v0(
                trnm_consensus_crypto::POCO_THREE_CHAIN_PROOF_CLASS_V0,
                proof_bytes,
                edge.new_validator_set(),
                edge.new_parameters(),
                expected,
                budget,
            )
            .map_err(|e| anyhow::anyhow!("ordinary sparse strict finality: {e}"))?
            .proof()
            .finalized_block()
            .header()
            .clone()
        };
        ensure!(
            final_header == header,
            "strict finality differs from complete retained header"
        );
        self.commit_epoch_p(prepared)
    }

    fn commit_epoch_p(
        &self,
        prepared: &PreparedNativeEpochExecutionV1,
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
        if p.status == 1 {
            let sequence = p
                .commit_sequence
                .context("committed epoch sequence missing")?;
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
        let sequence = metadata
            .durable_sequence
            .checked_add(1)
            .context("epoch commit sequence exhausted")?;
        let head = p.target_head()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
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
            ensure!(tx.execute("UPDATE native_epoch_edge_v1 SET phase=1,consumed_block=?,consumed_sequence=? WHERE binding=? AND phase=0 AND checkpoint_block=? AND checkpoint_root=?",
                params![p.block_id.as_slice(),sequence.to_be_bytes().as_slice(),binding.as_slice(),p.parent.block_id().as_bytes().as_slice(),p.parent.state_root().as_bytes().as_slice()])?==1,
                "epoch commit edge already consumed/conflicting");
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
        park_for_sigkill_commit_boundary_v0("epoch_before_commit");
        tx.commit()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("epoch_after_commit");
        drop(connection);
        sync_store_commit_boundary_v0(&self.path)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("epoch_after_fsync");
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
