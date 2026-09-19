//! Explicit schema6 first-new preparation and separately migrated schema7
//! strict finality/descendant owner. Neither mode grants Core or node authority.
use super::*;
use crate::epoch_recovery::{EpochRecoveryEvidenceV1, MAX_EPOCH_EVIDENCE_BYTES_V1};
use crate::AuthenticatedEpochApplicationEdgeV1;
use trnm_native_application::{
    NativeEpochBlockExecutionRequestV1, NativeEpochBlockPreviewRequestV1,
    NativeExecutedEpochBlockV1,
};
pub(in crate::durable) const SCHEMA_VERSION: u64 = 6;
#[path = "incremental_epoch_commit_v1.rs"]
mod commit;
#[path = "incremental_epoch_descendant_v1.rs"]
mod descendant;
pub use commit::CommittedNativeIncrementalEpochExecutionV1;
pub use descendant::{IncrementalEpochParentV1, PreparedNativeIncrementalEpochDescendantV1};
pub(in crate::durable) const COMMIT_SCHEMA_VERSION: u64 = 7;
fn epoch_schema(c: &Connection) -> Result<bool> {
    Ok(matches!(
        epoch_durable::schema_version(c)?,
        SCHEMA_VERSION | COMMIT_SCHEMA_VERSION
    ))
}
const SQL: &str = "
CREATE TABLE native_incremental_epoch_owner_v1 (
 id INTEGER PRIMARY KEY CHECK(id=1), source_anchor BLOB NOT NULL CHECK(length(source_anchor)=32),
 binding BLOB NOT NULL UNIQUE CHECK(length(binding)=32), checkpoint_p BLOB NOT NULL CHECK(length(checkpoint_p)=32),
 checkpoint_sequence BLOB NOT NULL CHECK(length(checkpoint_sequence)=8), evidence BLOB NOT NULL CHECK(length(evidence)<=67108864),
 checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT;
CREATE TABLE native_incremental_epoch_p_v1 (
 block BLOB PRIMARY KEY CHECK(length(block)=32), sequence BLOB NOT NULL UNIQUE CHECK(length(sequence)=8),
 kind INTEGER NOT NULL CHECK(kind=1), parent BLOB NOT NULL CHECK(length(parent)=104), edge BLOB NOT NULL CHECK(length(edge)=32),
 artifact BLOB NOT NULL CHECK(length(artifact)<=16777216), header BLOB NOT NULL CHECK(length(header)<=4096),
 storage_artifact BLOB NOT NULL CHECK(length(storage_artifact)=32), storage_sequence BLOB NOT NULL CHECK(length(storage_sequence)=8),
 replay_parent_version BLOB NOT NULL CHECK(length(replay_parent_version)=8), replay_parent_root BLOB NOT NULL CHECK(length(replay_parent_root)=32),
 replay_delta BLOB NOT NULL CHECK(length(replay_delta)<=16777216), lifecycle BLOB NOT NULL CHECK(length(lifecycle)<=1048576),
 digest BLOB NOT NULL CHECK(length(digest)=32)) STRICT, WITHOUT ROWID;";
#[derive(Clone)]
struct EdgeRow {
    anchor: [u8; 32],
    binding: [u8; 32],
    checkpoint_p: [u8; 32],
    sequence: u64,
    evidence: Vec<u8>,
    checksum: [u8; 32],
}
impl EdgeRow {
    fn digest(&self, config: &NativeApplicationConfigV0) -> [u8; 32] {
        hash_domain(
            "trnm.native-application.incremental-epoch-owner.v1",
            &[
                &config.store_id,
                &self.anchor,
                &self.binding,
                &self.checkpoint_p,
                &self.sequence.to_be_bytes(),
                &sha256_v0(&self.evidence),
            ],
        )
    }
}
fn row_blob(
    r: &rusqlite::Row<'_>,
    index: usize,
    min: usize,
    max: usize,
) -> rusqlite::Result<Vec<u8>> {
    match r.get_ref(index)? {
        rusqlite::types::ValueRef::Blob(bytes) if (min..=max).contains(&bytes.len()) => {
            Ok(bytes.to_vec())
        }
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn edge_row(c: &Connection) -> Result<EdgeRow> {
    c.query_row("SELECT source_anchor,binding,checkpoint_p,checkpoint_sequence,evidence,checksum FROM native_incremental_epoch_owner_v1 WHERE id=1", [], |r| {
        Ok((row_blob(r,0,32,32)?,row_blob(r,1,32,32)?,row_blob(r,2,32,32)?,row_blob(r,3,8,8)?,row_blob(r,4,1,MAX_EPOCH_EVIDENCE_BYTES_V1)?,row_blob(r,5,32,32)?))
    }).map_err(anyhow::Error::from).and_then(|r| Ok(EdgeRow {anchor:fixed(r.0)?,binding:fixed(r.1)?,checkpoint_p:fixed(r.2)?,sequence:number(r.3)?,evidence:r.4,checksum:fixed(r.5)?}))
}
fn audit_owner(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    metadata: &MetadataV0,
) -> Result<(Owner, EdgeRow)> {
    let base = load_owner(tx)?;
    let edge = edge_row(tx)?;
    ensure!(
        edge.evidence.len() <= MAX_EPOCH_EVIDENCE_BYTES_V1
            && edge.anchor == base.anchor
            && edge.checksum == edge.digest(config),
        "schema6 edge checksum/source"
    );
    ensure!(
        metadata.snapshot.is_empty()
            && metadata.snapshot_digest == sha256_v0(&[])
            && metadata.command_ids.is_empty()
            && metadata.signer_nonces.is_empty(),
        "schema6 exact checkpoint/no shadow snapshot"
    );
    ensure!(
        base.anchor == base.source_digest(config)
            && base.checksum == base.current_digest(&metadata.head),
        "schema6 base owner"
    );
    let storage = ni::read_incremental_head_v1(tx, &namespace(config))?;
    ensure!(
        storage.height == metadata.head.height().get()
            && storage.block == *metadata.head.block_id().as_bytes()
            && storage.root == *metadata.head.state_root().as_bytes()
            && storage.intent == *metadata.head.commit_id().as_bytes()
            && storage.checksum == base.storage_checksum,
        "schema6 committed storage cut"
    );
    let evidence = EpochRecoveryEvidenceV1::decode(&edge.evidence)?;
    let audit = evidence.audit_strict(
        &config.validator_set,
        &config.parameters,
        &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
    )?;
    let checkpoint = audit
        .activation
        .old_checkpoint_finality()
        .finalized_block()
        .header();
    ensure!(
        checkpoint.id().as_bytes() == base.source.block_id().as_bytes()
            && checkpoint.height().get() == base.source.height().get()
            && checkpoint.state_root().as_bytes() == base.source.state_root().as_bytes()
            && evidence.checkpoint_header == base.source_header,
        "schema6 checkpoint/context"
    );
    type CheckpointColumns = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let actual: CheckpointColumns = tx.query_row("SELECT p_digest,commit_sequence,artifact_digest,status,commit_id FROM native_durable_execution_p_v0 WHERE block_id=?1", [base.source.block_id().as_bytes().as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    ensure!(
        fixed::<32>(actual.0)? == edge.checkpoint_p
            && number(actual.1)? == edge.sequence
            && fixed::<32>(actual.2)? == sha256_v0(&evidence.checkpoint_artifact)
            && number(actual.3)? == P_STATUS_COMMITTED
            && fixed::<32>(actual.4)? == *base.source.commit_id().as_bytes(),
        "schema6 original committed P"
    );
    let committed = commit::load(tx)?;
    if let Some(record) = &committed {
        ensure!(
            epoch_durable::schema_version(tx)? == COMMIT_SCHEMA_VERSION,
            "epoch commit in prepare-only schema"
        );
        let p = commit::audit(tx, config, &edge, &base.source, &audit, record)?;
        if metadata.head == record.head {
            ensure!(
                base.commit_sequence == record.sequence
                    && base.replay == ReplayDelta::decode(&p.replay_delta)?.head,
                "epoch committed native/replay head"
            );
        } else {
            descendant::audit_committed_head(
                tx, config, &evidence, &edge, &base, metadata, record,
            )?;
        }
    } else {
        ensure!(
            metadata.head == base.source
                && base.commit_sequence == base.source_sequence
                && base.replay
                    == (ReplayHead {
                        version: 0,
                        root: base.source_replay
                    }),
            "uncommitted epoch source head"
        );
    }
    let ordinary: u64 = tx.query_row("SELECT count(*) FROM native_incremental_p_v1", [], |r| {
        r.get(0)
    })?;
    ensure!(
        ordinary == 0 || epoch_durable::schema_version(tx)? == COMMIT_SCHEMA_VERSION,
        "schema6 ordinary migration history unsupported"
    );
    let ordinary_max = descendant::audit_inventory(tx, metadata.durable_sequence, &base)?;
    let (count, bytes, maximum): (u64,u64,Option<Vec<u8>>) = tx.query_row("SELECT count(*),coalesce(sum(length(artifact)+length(header)+length(replay_delta)+length(lifecycle)),0),max(sequence) FROM native_incremental_epoch_p_v1", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    ensure!(
        count <= MAX_PREPARED as u64
            && bytes <= MAX_P_BYTES as u64
            && maximum
                .map(number)
                .transpose()?
                .unwrap_or(base.source_sequence)
                .max(committed.as_ref().map_or(0, |r| r.sequence))
                .max(ordinary_max)
                == metadata.durable_sequence,
        "schema6 P inventory/sequence"
    );
    let _ = ReplayReader::new(tx, Some(base.replay), &[])?;
    Ok((base, edge))
}
pub(in crate::durable) fn validate_metadata(
    c: &Connection,
    config: &NativeApplicationConfigV0,
    metadata: &MetadataV0,
) -> DurableResult<Vec<ValidatedPInventoryEntryV0>> {
    (|| -> Result<_> {
        let tx = c.unchecked_transaction()?;
        let (base, _) = audit_owner(&tx, config, metadata)?;
        validate_source_replay(&tx, config, &base)?;
        Ok(Vec::new())
    })()
    .map_err(fail)
}
pub(in crate::durable) fn audit_anchor(
    c: &Connection,
    config: &NativeApplicationConfigV0,
    metadata: &MetadataV0,
) -> DurableResult<[u8; 32]> {
    (|| -> Result<_> {
        let tx = c.unchecked_transaction()?;
        let (base, edge) = audit_owner(&tx, config, metadata)?;
        validate_source_replay(&tx, config, &base)?;
        Ok(edge.checksum)
    })()
    .map_err(fail)
}
pub(in crate::durable) fn verify_schema(c: &Connection) -> DurableResult<()> {
    (|| -> Result<_> {
        let mut reference = Connection::open_in_memory()?;
        initialize_schema_v0(&reference)?;
        let tx = reference.transaction()?;
        ni::install_incremental_schema_v1(&tx)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute_batch(replay::SCHEMA)?;
        tx.execute_batch(SQL)?;
        if epoch_durable::schema_version(c)? == COMMIT_SCHEMA_VERSION {
            tx.execute_batch(commit::SQL)?;
        }
        tx.commit()?;
        fn objects(c: &Connection) -> Result<Vec<(String, String, String)>> {
            let mut q = c.prepare(
                "SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' LIMIT 65",
            )?;
            let mut rows = q.query([])?;
            let mut values = Vec::new();
            while let Some(r) = rows.next()? {
                ensure!(values.len() < 64, "schema6 schema inventory capacity");
                let text = |i, max| -> Result<String> {
                    match r.get_ref(i)? {
                        rusqlite::types::ValueRef::Text(v) if v.len() <= max => {
                            Ok(std::str::from_utf8(v)?.to_owned())
                        }
                        _ => anyhow::bail!("schema6 schema field capacity/type"),
                    }
                };
                values.push((
                    text(0, 16)?,
                    text(1, 128)?,
                    normalize_sql_v0(&text(2, 16384)?),
                ));
            }
            values.sort();
            Ok(values)
        }
        ensure!(objects(c)? == objects(&reference)?, "schema6 closed schema");
        Ok(())
    })()
    .map_err(fail)
}
#[derive(Clone)]
struct EpochP {
    block: [u8; 32],
    sequence: u64,
    parent: ApplicationHeadV0,
    edge: [u8; 32],
    artifact: Vec<u8>,
    header: Vec<u8>,
    storage_artifact: [u8; 32],
    storage_sequence: u64,
    replay_parent: ReplayHead,
    replay_delta: Vec<u8>,
    lifecycle: Vec<u8>,
    digest: [u8; 32],
}
// Private validation inputs are rebuilt from either an owner-affine edge or
// independently audited retained evidence. They never mint an edge capability.
struct EpochPContext<'a> {
    parent: &'a ApplicationHeadV0,
    checkpoint_sequence: u64,
    binding: [u8; 32],
    terminal: &'a BlockHeader,
    set: &'a trnm_consensus_types::ValidatorSet,
    parameters: &'a ConsensusParametersV0,
}
fn require_live_edge(
    app: &DurableNativeApplicationV0,
    row: &EdgeRow,
    edge: &AuthenticatedEpochApplicationEdgeV1,
) -> Result<()> {
    ensure!(
        row.binding == edge.authorization_id()
            && *app
                .incremental_migration_pin
                .lock()
                .map_err(|_| anyhow::anyhow!("epoch migration pin"))?
                == Some(row.checksum),
        "epoch owner edge changed after recovery"
    );
    Ok(())
}
impl EpochP {
    fn target(&self) -> Result<ApplicationHeadV0> {
        let executed = self.executed()?;
        let r = executed.request();
        let replay = ReplayDelta::decode(&self.replay_delta)?;
        let id = hash_domain(
            "trnm.native-application.incremental-epoch-commit.v1",
            &[
                &self.digest,
                &self.block,
                r.expected().post_state_root().as_bytes(),
                &replay.head.root,
            ],
        );
        Ok(ApplicationHeadV0::new(
            r.preview().height(),
            r.block_id(),
            r.expected().post_state_root(),
            ApplicationCommitIdV0::new(id)?,
        ))
    }
    fn storage(&self) -> Result<ni::PreparedIncrementalDeltaV1> {
        let h = self.target()?;
        Ok(ni::PreparedIncrementalDeltaV1 {
            artifact: self.storage_artifact,
            block: self.block,
            height: h.height().get(),
            root: *h.state_root().as_bytes(),
            persist_sequence: self.storage_sequence,
        })
    }
    fn executed(&self) -> Result<NativeExecutedEpochBlockV1> {
        Ok(
            trnm_native_application::decode_native_executed_epoch_block_artifact_v1(
                &self.artifact,
            )?,
        )
    }
    fn digest(&self, config: &NativeApplicationConfigV0) -> [u8; 32] {
        hash_domain(
            "trnm.native-application.incremental-epoch-p.v1",
            &[
                &config.store_id,
                &self.sequence.to_be_bytes(),
                &[1],
                &head_bytes(&self.parent),
                &self.edge,
                &sha256_v0(&self.artifact),
                &sha256_v0(&self.header),
                &self.storage_artifact,
                &self.storage_sequence.to_be_bytes(),
                &self.replay_parent.version.to_be_bytes(),
                &self.replay_parent.root,
                &sha256_v0(&self.replay_delta),
                &sha256_v0(&self.lifecycle),
            ],
        )
    }
    fn validate(
        &self,
        config: &NativeApplicationConfigV0,
        edge: &AuthenticatedEpochApplicationEdgeV1,
    ) -> Result<()> {
        self.validate_context(
            config,
            &EpochPContext {
                parent: edge.application_parent(),
                checkpoint_sequence: edge.checkpoint_commit_sequence(),
                binding: edge.authorization_id(),
                terminal: edge.consensus_parent(),
                set: edge.new_validator_set(),
                parameters: edge.new_parameters(),
            },
        )
    }
    fn validate_context(
        &self,
        config: &NativeApplicationConfigV0,
        edge: &EpochPContext<'_>,
    ) -> Result<()> {
        let first_height = edge
            .terminal
            .height()
            .get()
            .checked_add(1)
            .context("epoch first height exhausted")?;
        ensure!(
            edge.parent.height().get().checked_add(3) == Some(first_height),
            "epoch exact gap"
        );
        ensure!(
            self.artifact.len() <= 16 * 1024 * 1024
                && self.header.len() <= 4096
                && self.replay_delta.len() <= MAX_REPLAY_DELTA
                && self.lifecycle.len() <= 1024 * 1024,
            "schema6 P bounds"
        );
        ensure!(
            self.digest == self.digest(config)
                && self.sequence > edge.checkpoint_sequence
                && self.parent == *edge.parent
                && self.edge == edge.binding,
            "schema6 P digest/parent"
        );
        let executed = self.executed()?;
        let request = executed.request();
        let preview = request.preview();
        ensure!(
            preview.chain_id().as_str() == edge.terminal.chain_id().as_str()
                && preview.genesis_hash().as_bytes() == edge.terminal.genesis_hash().as_bytes()
                && preview.application_parent() == edge.parent
                && preview.consensus_parent_id().as_bytes() == edge.terminal.id().as_bytes()
                && preview.consensus_parent_height().get() == edge.terminal.height().get()
                && preview.edge_binding().as_bytes() == &edge.binding
                && preview.height().get() == first_height
                && preview.active_validator_set_id().as_bytes() == edge.set.id().as_bytes()
                && preview.timestamp_ms() > edge.terminal.timestamp_ms(),
            "schema7 retained epoch request context"
        );
        let h = header(&self.header)?;
        ensure!(
            self.block == *request.block_id().as_bytes()
                && h.id().as_bytes() == request.block_id().as_bytes()
                && h.parent_id() == edge.terminal.id()
                && h.height().get() == first_height
                && h.timestamp_ms() == request.preview().timestamp_ms()
                && h.block_kind() == trnm_consensus_types::BlockKind::EpochHandoff
                && h.validator_set_id() == edge.set.id()
                && h.consensus_parameters_hash() == edge.parameters.hash()
                && h.epoch() == edge.set.epoch()
                && h.chain_id() == edge.set.chain_id()
                && h.genesis_hash() == edge.set.genesis_hash(),
            "schema6 exact first-new header"
        );
        let expected = request.expected();
        ensure!(
            h.payload_root().as_bytes() == expected.payload_root().as_bytes()
                && h.state_root().as_bytes() == expected.post_state_root().as_bytes()
                && h.receipts_root().as_bytes() == expected.receipts_root().as_bytes()
                && h.evidence_root().as_bytes() == expected.evidence_root().as_bytes(),
            "schema6 header roots"
        );
        let exact = crate::poco_checkpoint::native_execution_from_receipts_v0(
            request.preview().transactions(),
            executed.receipts(),
        )?;
        ensure!(
            exact
                .application_payload()
                .payload_root()
                .map_err(|e| anyhow::anyhow!("payload: {e:?}"))?
                .as_bytes()
                == h.payload_root().as_bytes()
                && exact
                    .execution_receipts()
                    .receipts_root()
                    .map_err(|e| anyhow::anyhow!("receipts: {e:?}"))?
                    .as_bytes()
                    == h.receipts_root().as_bytes(),
            "schema6 actual receipts"
        );
        let replay = ReplayDelta::decode(&self.replay_delta)?;
        ensure!(
            self.replay_parent.version.checked_add(1) == Some(replay.head.version),
            "schema6 replay successor"
        );
        Ok(())
    }
    fn validate_storage(&self, tx: &rusqlite::Transaction<'_>) -> Result<()> {
        let storage = tx.query_row(
            "SELECT persist_sequence,block_id,edge,target_height,parent_id,parent_height,parent_root FROM ni_prepared WHERE artifact=?1",
            [self.storage_artifact.as_slice()],
            |r| Ok((row_blob(r,0,8,8)?,row_blob(r,1,32,32)?,row_blob(r,2,32,32)?,row_blob(r,3,8,8)?,row_blob(r,4,32,32)?,row_blob(r,5,8,8)?,row_blob(r,6,32,32)?)),
        )?;
        ensure!(
            number(storage.0)? == self.storage_sequence
                && fixed::<32>(storage.1)? == self.block
                && fixed::<32>(storage.2)? == self.edge
                && number(storage.3)? == self.target()?.height().get()
                && fixed::<32>(storage.4)? == *self.parent.block_id().as_bytes()
                && number(storage.5)? == self.parent.height().get()
                && fixed::<32>(storage.6)? == *self.parent.state_root().as_bytes(),
            "schema6 P storage identity/sequence"
        );
        Ok(())
    }
}
fn load_epoch_p(c: &Connection, block: [u8; 32]) -> Result<Option<EpochP>> {
    let r=c.query_row("SELECT sequence,kind,parent,edge,CASE WHEN length(artifact)<=16777216 THEN artifact ELSE NULL END,CASE WHEN length(header)<=4096 THEN header ELSE NULL END,storage_artifact,storage_sequence,replay_parent_version,replay_parent_root,CASE WHEN length(replay_delta)<=16777216 THEN replay_delta ELSE NULL END,CASE WHEN length(lifecycle)<=1048576 THEN lifecycle ELSE NULL END,digest FROM native_incremental_epoch_p_v1 WHERE block=?1",[block.as_slice()],|r|Ok((row_blob(r,0,8,8)?,r.get::<_,u8>(1)?,row_blob(r,2,104,104)?,row_blob(r,3,32,32)?,row_blob(r,4,1,16*1024*1024)?,row_blob(r,5,1,4096)?,row_blob(r,6,32,32)?,row_blob(r,7,8,8)?,row_blob(r,8,8,8)?,row_blob(r,9,32,32)?,row_blob(r,10,1,MAX_REPLAY_DELTA)?,row_blob(r,11,0,1024*1024)?,row_blob(r,12,32,32)?))).optional()?;
    r.map(|r| {
        ensure!(r.1 == 1, "schema6 artifact kind");
        Ok(EpochP {
            block,
            sequence: number(r.0)?,
            parent: decode_head(&r.2)?,
            edge: fixed(r.3)?,
            artifact: r.4,
            header: r.5,
            storage_artifact: fixed(r.6)?,
            storage_sequence: number(r.7)?,
            replay_parent: ReplayHead {
                version: number(r.8)?,
                root: fixed(r.9)?,
            },
            replay_delta: r.10,
            lifecycle: r.11,
            digest: fixed(r.12)?,
        })
    })
    .transpose()
}
/// Actual first-new native P backed by changed JMT/replay nodes. No commit or
/// Core authority; non-Clone and only issued after strict fresh native readback.
#[must_use]
pub struct PreparedNativeIncrementalEpochExecutionV1 {
    owner: Arc<()>,
    p: EpochP,
    commit_sequence: Option<u64>,
}
impl PreparedNativeIncrementalEpochExecutionV1 {
    pub fn executed(&self) -> Result<NativeExecutedEpochBlockV1> {
        self.p.executed()
    }
    pub fn header(&self) -> Result<BlockHeader> {
        header(&self.p.header)
    }
    pub fn application_parent(&self) -> &ApplicationHeadV0 {
        &self.p.parent
    }
    pub const fn p_digest(&self) -> [u8; 32] {
        self.p.digest
    }
    pub fn target_head(&self) -> Result<ApplicationHeadV0> {
        self.p.target()
    }
    pub const fn commit_sequence(&self) -> Option<u64> {
        self.commit_sequence
    }
    pub const fn persist_sequence(&self) -> u64 {
        self.p.sequence
    }
    pub const fn edge_binding(&self) -> [u8; 32] {
        self.p.edge
    }
    pub fn artifact_checksum(&self) -> [u8; 32] {
        sha256_v0(&self.p.artifact)
    }
    pub fn overlay_checksum(&self) -> [u8; 32] {
        hash_domain(
            "trnm.native-application.incremental-epoch-overlay.v1",
            &[
                &self.p.edge,
                &self.p.storage_artifact,
                &self.p.replay_parent.root,
                &sha256_v0(&self.p.replay_delta),
                &sha256_v0(&self.p.lifecycle),
            ],
        )
    }
    pub fn application_payload_and_receipts(
        &self,
    ) -> Result<(
        trnm_consensus_types::ApplicationPayloadV0,
        trnm_consensus_types::ExecutionReceiptsV0,
    )> {
        let executed = self.executed()?;
        let exact = crate::poco_checkpoint::native_execution_from_receipts_v0(
            executed.request().preview().transactions(),
            executed.receipts(),
        )?;
        Ok((
            exact.application_payload().clone(),
            exact.execution_receipts().clone(),
        ))
    }
    pub fn belongs_to_application_at_path(
        &self,
        app: &DurableNativeApplicationV0,
        path: &Path,
    ) -> bool {
        path == app.path()
            && Arc::ptr_eq(&self.owner, &app.owner_affinity)
            && app
                .reopen_prepared_incremental_epoch_v1(self.p.block, self.p.digest)
                .is_ok_and(|fresh| {
                    fresh.p.sequence == self.p.sequence
                        && fresh.commit_sequence == self.commit_sequence
                })
    }
}
impl crate::complete::CompleteExecutionStoreV1 for EpochView<'_> {
    fn complete_live_values_v1(&self, version: u64) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        self.0.complete_live_values_v1(version)
    }
    fn validate_epoch_parent_v1(&self, edge: &AuthenticatedEpochApplicationEdgeV1) -> Result<()> {
        ensure!(
            self.0.state.version() == edge.application_parent().height().get()
                && self.0.state.root().0 == *edge.application_parent().state_root().as_bytes(),
            "schema6 execution parent"
        );
        Ok(())
    }
    fn plan_epoch_v1(
        &self,
        edge: &AuthenticatedEpochApplicationEdgeV1,
        writes: Vec<crate::store::CompleteStateWriteV0>,
    ) -> Result<crate::store::CompleteStatePlanV0> {
        ni::epoch_candidate_v1::plan(&self.0.state, edge, writes)
    }
}
struct EpochView<'a>(ExecutionView<'a>);
impl TreeReader for EpochView<'_> {
    fn get_node_option(&self, k: &NodeKey) -> Result<Option<Node>> {
        self.0.get_node_option(k)
    }
    fn get_value_option(&self, v: u64, k: KeyHash) -> Result<Option<Vec<u8>>> {
        self.0.get_value_option(v, k)
    }
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        self.0.get_rightmost_leaf()
    }
}
impl HasPreimage for EpochView<'_> {
    fn preimage(&self, k: KeyHash) -> Result<Option<Vec<u8>>> {
        self.0.preimage(k)
    }
}
impl NativeExecutionStoreV0 for EpochView<'_> {
    fn parent_version_v0(&self) -> Result<u64> {
        self.0.parent_version_v0()
    }
    fn parent_root_v0(&self) -> Result<RootHash> {
        self.0.parent_root_v0()
    }
    fn chain_id_v0(&self) -> Result<&str> {
        self.0.chain_id_v0()
    }
    fn authorized_signers_v0(&self) -> Result<&[AuthorizedSignerV0]> {
        self.0.authorized_signers_v0()
    }
    fn signer_policy_commitment_v0(&self) -> Result<[u8; 32]> {
        self.0.signer_policy_commitment_v0()
    }
    fn consensus_parameters_v0(&self) -> Result<ConsensusParametersV0> {
        self.0.consensus_parameters_v0()
    }
    fn committed_command_id_v0(&self, id: &str) -> Result<bool> {
        self.0.committed_command_id_v0(id)
    }
    fn committed_signer_nonce_v0(&self, id: &str, n: u64) -> Result<bool> {
        self.0.committed_signer_nonce_v0(id, n)
    }
}
impl DurableNativeApplicationV0 {
    /// Explicit schema5-at-C to schema6 migration; no state execution occurs.
    pub fn upgrade_incremental_epoch_schema_v1(
        &self,
        edge: &AuthenticatedEpochApplicationEdgeV1,
    ) -> Result<()> {
        drop(self.confirm_epoch_application_edge_v1(edge)?);
        let _guard = self.lock_operation()?;
        let mut c = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let metadata = load_metadata_v0(&c, &self.config)?;
        if epoch_durable::schema_version(&c)? == SCHEMA_VERSION {
            let tx = c.transaction()?;
            let (_, actual) = audit_owner(&tx, &self.config, &metadata)?;
            ensure!(
                actual.binding == edge.authorization_id()
                    && actual.evidence == edge.recovery_evidence().encode()?,
                "schema6 migration retry"
            );
            ensure!(
                *self
                    .incremental_migration_pin
                    .lock()
                    .map_err(|_| anyhow::anyhow!("migration lock"))?
                    == Some(actual.checksum),
                "schema6 live migration pin"
            );
            drop(tx);
            drop(c);
            sync_store_commit_boundary_v0(&self.path)?;
            return Ok(());
        }
        ensure!(
            epoch_durable::schema_version(&c)? == super::SCHEMA_VERSION,
            "explicit schema5 checkpoint migration required"
        );
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let base = self.pinned_incremental_owner(&tx, &metadata)?;
        ensure!(
            base.source == metadata.head && base.source == *edge.application_parent(),
            "schema6 requires original migrated checkpoint"
        );
        let count: u64 = tx.query_row("SELECT count(*) FROM native_incremental_p_v1", [], |r| {
            r.get(0)
        })?;
        ensure!(count == 0, "schema6 no ordinary incremental P");
        let mut row = EdgeRow {
            anchor: base.anchor,
            binding: edge.authorization_id(),
            checkpoint_p: edge.durable_checkpoint().p_digest_v0(),
            sequence: edge.checkpoint_commit_sequence(),
            evidence: edge.recovery_evidence().encode()?,
            checksum: [0; 32],
        };
        row.checksum = row.digest(&self.config);
        tx.execute_batch(SQL)?;
        tx.execute(
            "INSERT INTO native_incremental_epoch_owner_v1 VALUES(1,?,?,?,?,?,?)",
            params![
                row.anchor.as_slice(),
                row.binding.as_slice(),
                row.checkpoint_p.as_slice(),
                row.sequence.to_be_bytes().as_slice(),
                row.evidence,
                row.checksum.as_slice()
            ],
        )?;
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET schema_version=?1 WHERE singleton=1 AND schema_version=?2 AND durable_sequence=?3",params![SCHEMA_VERSION.to_be_bytes().as_slice(),super::SCHEMA_VERSION.to_be_bytes().as_slice(),metadata.durable_sequence.to_be_bytes().as_slice()])?==1,"schema6 migration CAS");
        tx.commit()?;
        drop(c);
        sync_store_commit_boundary_v0(&self.path)?;
        fresh_validate_v0(&self.path, &self.config)?;
        *self
            .incremental_migration_pin
            .lock()
            .map_err(|_| anyhow::anyhow!("migration lock"))? = Some(row.checksum);
        Ok(())
    }
    pub fn recover_incremental_epoch_edge_v1(&self) -> Result<AuthenticatedEpochApplicationEdgeV1> {
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        ensure!(epoch_schema(&c)?, "incremental epoch schema required");
        let tx = c.unchecked_transaction()?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let (_, row) = audit_owner(&tx, &self.config, &m)?;
        ensure!(
            *self
                .incremental_migration_pin
                .lock()
                .map_err(|_| anyhow::anyhow!("migration lock"))?
                == Some(row.checksum),
            "schema6 migration owner changed"
        );
        let evidence = EpochRecoveryEvidenceV1::decode(&row.evidence)?;
        drop(tx);
        drop(c);
        let executed = decode_native_executed_block_artifact_v0(&evidence.checkpoint_artifact)?;
        let r = executed.request();
        let h = header(&evidence.checkpoint_header)?;
        let request = NativeBlockPreviewRequestV0::new(
            r.chain_id().clone(),
            r.genesis_hash(),
            r.parent().clone(),
            r.height(),
            r.timestamp_ms(),
            r.active_validator_set_id(),
            r.transactions().to_vec(),
        )?;
        let journal = crate::poco_preparation_journal::PocoPreparationJournalV0::open_existing(
            crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&self.path),
        )?;
        journal.require_retained_bound(evidence.preparation_id, &evidence.checkpoint_header)?;
        let prepared = self.prepare_native_poco_checkpoint_v0(
            &request,
            h.view(),
            h.proposer_id(),
            &evidence.cutoff_finality,
            &evidence.cutoff_parent,
        )?;
        let confirmed = self.confirm_poco_checkpoint_v0(
            prepared,
            &evidence.checkpoint_finality,
            &evidence.anchor,
        )?;
        ensure!(
            confirmed.recovery_evidence.encode()? == row.evidence
                && confirmed.handoff_authorization_id() == row.binding
                && confirmed.durable_row().p_digest_v0() == row.checkpoint_p,
            "schema6 reconstructed native edge"
        );
        confirmed.into_epoch_application_edge_v1()
    }
    pub fn preview_incremental_epoch_block_v1(
        &self,
        edge: &AuthenticatedEpochApplicationEdgeV1,
        request: &NativeEpochBlockPreviewRequestV1,
    ) -> Result<NativeBlockPreviewV0> {
        ensure!(
            edge.durable_checkpoint()
                .belongs_to_application_at_path_v0(self, self.path()),
            "schema6 foreign edge"
        );
        let _guard = self.lock_operation()?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        ensure!(epoch_schema(&c)?, "incremental epoch schema required");
        let tx = c.unchecked_transaction()?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let (base, row) = audit_owner(&tx, &self.config, &m)?;
        ensure!(
            row.binding == edge.authorization_id()
                && *self
                    .incremental_migration_pin
                    .lock()
                    .map_err(|_| anyhow::anyhow!("migration lock"))?
                    == Some(row.checksum),
            "schema6 edge mismatch"
        );
        let parent = ResolvedParent {
            state: ni::IncrementalParentV1::Committed(*m.head.block_id().as_bytes()),
            replay: Vec::new(),
            digest: None,
        };
        let view = EpochView(execution_view(&tx, &self.config, &base, &parent)?);
        crate::complete::preview_complete_epoch_block_v1(&view, edge, request)
    }
    pub fn execute_incremental_epoch_block_v1(
        &self,
        edge: &AuthenticatedEpochApplicationEdgeV1,
        request: NativeEpochBlockExecutionRequestV1,
        h: &BlockHeader,
    ) -> Result<PreparedNativeIncrementalEpochExecutionV1> {
        ensure!(
            edge.durable_checkpoint()
                .belongs_to_application_at_path_v0(self, self.path()),
            "schema6 foreign edge"
        );
        let _guard = self.lock_operation()?;
        let mut c = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        ensure!(epoch_schema(&c)?, "incremental epoch schema required");
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let (base, row) = audit_owner(&tx, &self.config, &m)?;
        ensure!(
            row.binding == edge.authorization_id()
                && *self
                    .incremental_migration_pin
                    .lock()
                    .map_err(|_| anyhow::anyhow!("migration lock"))?
                    == Some(row.checksum),
            "schema6 live edge/source"
        );
        if let Some(prior) = load_epoch_p(&tx, *request.block_id().as_bytes())? {
            prior.validate(&self.config, edge)?;
            ensure!(
                prior.executed()?.request() == &request && header(&prior.header)? == *h,
                "schema6 exact retry"
            );
            drop(tx);
            drop(c);
            sync_store_commit_boundary_v0(&self.path)?;
            drop(_guard);
            return self.reopen_prepared_incremental_epoch_v1(prior.block, prior.digest);
        }
        let parent = ResolvedParent {
            state: ni::IncrementalParentV1::Committed(*m.head.block_id().as_bytes()),
            replay: Vec::new(),
            digest: None,
        };
        let view = EpochView(execution_view(&tx, &self.config, &base, &parent)?);
        let computed = crate::complete::compute_complete_epoch_native_block_v1(
            &view,
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
        let keys = computed
            .replay_identities
            .iter()
            .map(|i| replay::command_key(i.command_id()))
            .chain(
                computed
                    .replay_identities
                    .iter()
                    .map(|i| replay::nonce_key(i.signer_id(), i.nonce())),
            )
            .collect::<Result<Vec<_>>>()?;
        let replay_parent = view.0.replay.head.context("schema6 replay parent")?;
        let replay = view.0.replay.append(keys)?;
        drop(view);
        let delta = ni::epoch_candidate_v1::stage(
            &tx,
            &namespace(&self.config),
            edge,
            *executed.request().block_id().as_bytes(),
            &computed.plan,
        )?;
        let mut p = EpochP {
            block: *executed.request().block_id().as_bytes(),
            sequence: m
                .durable_sequence
                .checked_add(1)
                .context("schema6 sequence exhausted")?,
            parent: edge.application_parent().clone(),
            edge: edge.authorization_id(),
            artifact: trnm_native_application::encode_native_executed_epoch_block_artifact_v1(
                &executed,
            )?,
            header: h
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("header: {e:?}"))?,
            storage_artifact: delta.artifact,
            storage_sequence: delta.persist_sequence,
            replay_parent,
            replay_delta: replay.encode()?,
            lifecycle: serde_json::to_vec(&computed.final_lifecycle)?,
            digest: [0; 32],
        };
        p.digest = p.digest(&self.config);
        p.validate(&self.config, edge)?;
        let(count,bytes):(u64,u64)=tx.query_row("SELECT count(*),coalesce(sum(length(artifact)+length(header)+length(replay_delta)+length(lifecycle)),0) FROM native_incremental_epoch_p_v1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        ensure!(
            count < MAX_PREPARED as u64
                && bytes
                    .checked_add(
                        (p.artifact.len()
                            + p.header.len()
                            + p.replay_delta.len()
                            + p.lifecycle.len()) as u64
                    )
                    .is_some_and(|n| n <= MAX_P_BYTES as u64),
            "schema6 P capacity"
        );
        tx.execute(
            "INSERT INTO native_incremental_epoch_p_v1 VALUES(?,?,1,?,?,?,?,?,?,?,?,?,?,?)",
            params![
                p.block.as_slice(),
                p.sequence.to_be_bytes().as_slice(),
                head_bytes(&p.parent),
                p.edge.as_slice(),
                p.artifact,
                p.header,
                p.storage_artifact.as_slice(),
                p.storage_sequence.to_be_bytes().as_slice(),
                p.replay_parent.version.to_be_bytes().as_slice(),
                p.replay_parent.root.as_slice(),
                p.replay_delta,
                p.lifecycle,
                p.digest.as_slice()
            ],
        )?;
        ensure!(tx.execute("UPDATE native_application_metadata_v0 SET durable_sequence=?1 WHERE singleton=1 AND durable_sequence=?2 AND schema_version=?3",params![p.sequence.to_be_bytes().as_slice(),m.durable_sequence.to_be_bytes().as_slice(),epoch_durable::schema_version(&tx)?.to_be_bytes().as_slice()])?==1,"schema6 P sequence CAS");
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_epoch_before_commit");
        tx.commit()?;
        drop(c);
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_epoch_after_commit_before_fsync");
        sync_store_commit_boundary_v0(&self.path)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_epoch_after_fsync_before_readback");
        drop(_guard);
        self.reopen_prepared_incremental_epoch_v1(p.block, p.digest)
    }
    pub fn confirm_prepared_incremental_epoch_execution_v1(
        &self,
        p: &PreparedNativeIncrementalEpochExecutionV1,
    ) -> Result<PreparedNativeIncrementalEpochExecutionV1> {
        ensure!(
            Arc::ptr_eq(&p.owner, &self.owner_affinity),
            "incremental epoch P readback foreign owner"
        );
        let fresh = self.reopen_prepared_incremental_epoch_v1(p.p.block, p.p.digest)?;
        ensure!(
            fresh.p.sequence == p.p.sequence,
            "incremental epoch P sequence changed"
        );
        Ok(fresh)
    }
    pub fn reopen_prepared_incremental_epoch_v1(
        &self,
        block: [u8; 32],
        expected: [u8; 32],
    ) -> Result<PreparedNativeIncrementalEpochExecutionV1> {
        let edge = self.recover_incremental_epoch_edge_v1()?;
        let _guard = self.lock_operation()?;
        let c = open_immutable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let tx = c.unchecked_transaction()?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let (base, row) = audit_owner(&tx, &self.config, &m)?;
        require_live_edge(self, &row, &edge)?;
        let p = load_epoch_p(&tx, block)?.context("schema6 P missing")?;
        p.validate(&self.config, &edge)?;
        let committed = commit::load(&tx)?.filter(|r| r.block == p.block);
        ensure!(
            p.digest == expected && (committed.is_some() || p.replay_parent == base.replay),
            "schema6 P expected/replay"
        );
        let reader = ni::open_incremental_reader_v1(
            &tx,
            &namespace(&self.config),
            ni::IncrementalParentV1::Prepared(p.storage_artifact),
        )?;
        ensure!(
            reader.version() == edge.first_application_height()
                && reader.root().0
                    == *p
                        .executed()?
                        .request()
                        .expected()
                        .post_state_root()
                        .as_bytes(),
            "schema6 P storage root"
        );
        p.validate_storage(&tx)?;
        let deltas = [ReplayDelta::decode(&p.replay_delta)?];
        let _ = ReplayReader::new(
            &tx,
            Some(base.replay),
            if committed.is_some() { &[] } else { &deltas },
        )?;
        Ok(PreparedNativeIncrementalEpochExecutionV1 {
            owner: Arc::clone(&self.owner_affinity),
            p,
            commit_sequence: committed.map(|r| r.sequence),
        })
    }
}

#[cfg(all(test, feature = "test-fixtures"))]
mod tests {
    use super::*;
    use crate::test_fixtures::{
        build_native_checkpoint_fixture_v1, native_checkpoint_fixture_config_v1,
    };
    use trnm_consensus_types::{
        BlockKind, EvidenceRoot, Height, PayloadDigest, ReceiptsRoot, StateRoot, View,
    };

    #[test]
    fn actual_first_new_incremental_p_reopens_without_snapshot_or_seal_versions() {
        let d = tempfile::tempdir().unwrap();
        let path = std::env::var_os("TRNM_NATIVE_INCREMENTAL_EPOCH_SIGKILL_STORE")
            .map(PathBuf::from)
            .unwrap_or_else(|| d.path().join("native.sqlite3"));
        let f = build_native_checkpoint_fixture_v1(&path);
        let app = f.application;
        let edge = app
            .confirm_poco_checkpoint_v0(
                f.checkpoint,
                &f.checkpoint_finality_bytes,
                &f.handoff_anchor_bytes,
            )
            .unwrap()
            .into_epoch_application_edge_v1()
            .unwrap();
        let foreign = crate::test_fixtures::open_native_checkpoint_fixture_genesis_v1(
            &d.path().join("foreign.sqlite3"),
        );
        assert!(foreign.upgrade_incremental_epoch_schema_v1(&edge).is_err());
        drop(foreign);
        let request = edge.preview_request_v1(11_000, Vec::new()).unwrap();
        let reference = app.preview_epoch_block_v1(&edge, &request).unwrap();
        assert!(app.upgrade_incremental_epoch_schema_v1(&edge).is_err());
        app.upgrade_incremental_schema_v1(edge.application_parent(), &f.ordinary_headers[0])
            .unwrap_err();
        let checkpoint = trnm_consensus_types::decode_block_header_v0_exact(
            &edge.recovery_evidence().checkpoint_header,
        )
        .unwrap();
        app.upgrade_incremental_schema_v1(edge.application_parent(), &checkpoint)
            .unwrap();
        assert!(app.confirm_ordinary_schema_v0().is_err());
        app.upgrade_incremental_epoch_schema_v1(&edge).unwrap();
        app.upgrade_incremental_epoch_schema_v1(&edge).unwrap();
        let preview = app
            .preview_incremental_epoch_block_v1(&edge, &request)
            .unwrap();
        assert_eq!(preview.post_state_root(), reference.post_state_root());
        assert_eq!(preview.receipts_root(), reference.receipts_root());
        let set = edge.new_validator_set();
        let h = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(1),
            Height::new(11),
            BlockKind::EpochHandoff,
            edge.consensus_parent().id(),
            set.validators()[0].id(),
            set.id(),
            edge.new_parameters().hash(),
            PayloadDigest::new(*preview.payload_root().as_bytes()),
            StateRoot::new(*preview.post_state_root().as_bytes()),
            ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*preview.evidence_root().as_bytes()),
            11_000,
            None,
        )
        .unwrap();
        let r = NativeEpochBlockExecutionRequestV1::new(
            request,
            BlockIdV0::new(*h.id().as_bytes()).unwrap(),
            trnm_native_application::NativeExpectedBlockCommitmentsV0::new(
                preview.payload_root(),
                preview.post_state_root(),
                preview.receipts_root(),
                preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        std::fs::write(path.with_extension("epoch-block"), h.id().as_bytes()).unwrap();
        let p = app
            .execute_incremental_epoch_block_v1(&edge, r.clone(), &h)
            .unwrap();
        let retry = app
            .execute_incremental_epoch_block_v1(&edge, r, &h)
            .unwrap();
        assert_eq!(p.p_digest(), retry.p_digest());
        assert_eq!(p.persist_sequence(), retry.persist_sequence());
        assert!(p.belongs_to_application_at_path(&app, &path));
        assert_eq!(
            app.confirmed_committed_head_v0().unwrap(),
            *edge.application_parent()
        );
        let c = Connection::open(&path).unwrap();
        let snapshots: u64 = c
            .query_row(
                "SELECT length(authenticated_snapshot) FROM native_application_metadata_v0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(snapshots, 0);
        let seals: u64 = c
            .query_row(
                "SELECT count(*) FROM ni_roots WHERE version IN(?1,?2)",
                params![
                    9u64.to_be_bytes().as_slice(),
                    10u64.to_be_bytes().as_slice()
                ],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(seals, 0);
        let tx = c.unchecked_transaction().unwrap();
        let base = load_owner(&tx).unwrap();
        let parent = ResolvedParent {
            state: ni::IncrementalParentV1::Committed(
                *edge.application_parent().block_id().as_bytes(),
            ),
            replay: Vec::new(),
            digest: None,
        };
        let view = EpochView(execution_view(&tx, &app.config, &base, &parent).unwrap());
        let plan = crate::complete::compute_complete_epoch_native_block_v1(
            &view,
            &edge,
            p.executed().unwrap().request().preview(),
        )
        .unwrap()
        .plan;
        drop(view);
        assert!(ni::stage_incremental_plan_v1(
            &tx,
            &namespace(&app.config),
            parent.state,
            *h.id().as_bytes(),
            &plan
        )
        .is_err());
        let storage = ni::read_incremental_head_v1(&tx, &namespace(&app.config)).unwrap();
        let delta = ni::PreparedIncrementalDeltaV1 {
            artifact: p.p.storage_artifact,
            block: p.p.block,
            height: 11,
            root: *h.state_root().as_bytes(),
            persist_sequence: p.p.storage_sequence,
        };
        assert!(ni::apply_incremental_delta_v1(
            &tx,
            &namespace(&app.config),
            &storage,
            &delta,
            [99; 32],
            0
        )
        .is_err());
        drop(tx);
        drop(c);
        let digest = p.p_digest();
        drop(edge);
        drop(app);
        let reopened =
            DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1()).unwrap();
        assert!(!p.belongs_to_application_at_path(&reopened, &path));
        let recovered = reopened
            .reopen_prepared_incremental_epoch_v1(*h.id().as_bytes(), digest)
            .unwrap();
        assert_eq!(recovered.header().unwrap(), h);
        assert!(reopened
            .reopen_prepared_incremental_epoch_v1(*h.id().as_bytes(), [42; 32])
            .is_err());
        let c = Connection::open(&path).unwrap();
        let original_edge = edge_row(&c).unwrap();
        for column in ["binding", "checkpoint_p", "checksum"] {
            c.execute(
                &format!("UPDATE native_incremental_epoch_owner_v1 SET {column}=?1"),
                [[77u8; 32].as_slice()],
            )
            .unwrap();
            assert!(reopened.recover_incremental_epoch_edge_v1().is_err());
            let original = match column {
                "binding" => original_edge.binding,
                "checkpoint_p" => original_edge.checkpoint_p,
                _ => original_edge.checksum,
            };
            c.execute(
                &format!("UPDATE native_incremental_epoch_owner_v1 SET {column}=?1"),
                [original.as_slice()],
            )
            .unwrap();
        }
        assert!(recovered.belongs_to_application_at_path(&reopened, &path));
        c.execute(
            "UPDATE native_incremental_epoch_p_v1 SET storage_sequence=?1",
            [999u64.to_be_bytes().as_slice()],
        )
        .unwrap();
        assert!(!recovered.belongs_to_application_at_path(&reopened, &path));
        c.execute(
            "UPDATE native_incremental_epoch_p_v1 SET storage_sequence=?1",
            [recovered.p.storage_sequence.to_be_bytes().as_slice()],
        )
        .unwrap();
        assert!(recovered.belongs_to_application_at_path(&reopened, &path));
        let sidecar = crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&path);
        std::fs::rename(&sidecar, path.with_extension("missing-preparation")).unwrap();
        assert!(reopened.recover_incremental_epoch_edge_v1().is_err());
    }
    #[cfg(unix)]
    #[test]
    fn incremental_epoch_sigkill_prepare_cuts_keep_atomic_p_and_strict_recovery() {
        for stage in [
            "incremental_epoch_before_commit",
            "incremental_epoch_after_commit_before_fsync",
            "incremental_epoch_after_fsync_before_readback",
        ] {
            let d = tempfile::tempdir().unwrap();
            let path = d.path().join("epoch.sqlite3");
            let marker = d.path().join("ready");
            let mut child=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","durable::incremental_owner_v1::epoch_candidate_v1::tests::actual_first_new_incremental_p_reopens_without_snapshot_or_seal_versions","--nocapture"])
                .env("TRNM_NATIVE_INCREMENTAL_EPOCH_SIGKILL_STORE",&path)
                .env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE",stage)
                .env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER",&marker).spawn().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
            while !marker.exists() && std::time::Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if !marker.exists() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("epoch child did not reach {stage}");
            }
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            let app =
                DurableNativeApplicationV0::open(&path, native_checkpoint_fixture_config_v1())
                    .unwrap();
            assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 8);
            let edge = app.recover_incremental_epoch_edge_v1().unwrap();
            assert_eq!(edge.first_application_height(), 11);
            let block: [u8; 32] = std::fs::read(path.with_extension("epoch-block"))
                .unwrap()
                .try_into()
                .unwrap();
            let c = Connection::open(&path).unwrap();
            let p = load_epoch_p(&c, block).unwrap();
            let expected = if stage == "incremental_epoch_before_commit" {
                0
            } else {
                1
            };
            assert_eq!(usize::from(p.is_some()), expected);
            for table in [
                "ni_prepared",
                "ni_epoch_edge",
                "native_incremental_epoch_p_v1",
            ] {
                assert_eq!(
                    c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                        .get::<_, usize>(0))
                        .unwrap(),
                    expected
                );
            }
            if let Some(p) = p {
                assert!(app
                    .reopen_prepared_incremental_epoch_v1(block, p.digest)
                    .unwrap()
                    .belongs_to_application_at_path(&app, &path));
            }
        }
    }
}
