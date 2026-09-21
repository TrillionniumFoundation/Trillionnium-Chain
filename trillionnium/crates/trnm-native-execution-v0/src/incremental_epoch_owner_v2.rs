//! Explicit schema7→11 migration, immutable source and closed current inventory.
//! Successor attachment and preparation retain their explicit strict context.
//! Consumed successors remain fenced until the complete first-commit ledger.
use super::*;
use rusqlite::types::{Value, ValueRef};
#[path = "incremental_epoch_progress_v2.rs"]
mod progress;
pub use progress::{
    CommittedIncrementalEpochPreHandoffV2, CommittedNativeIncrementalEpochV2,
    ComputedIncrementalEpochSelectionV2, IncrementalPreHandoffPreimagesV2,
    InstalledIncrementalEpochEdgeV2, PreparedIncrementalCheckpointV2, PreparedIncrementalFirstV2,
    PreparedNativeIncrementalEpochV2,
};
pub(in crate::durable) const SCHEMA_VERSION: u64 = 11;
const MAX_PROOF: usize = 8 * 1024 * 1024;
const TABLES: [&str; 6] = [
    "native_incremental_epoch_owner_v2",
    "native_incremental_epoch_edge_v2",
    "native_incremental_epoch_p_context_v2",
    "native_incremental_epoch_pre_handoff_v2",
    "native_incremental_epoch_first_commit_v2",
    "native_incremental_epoch_ordinary_commit_v2",
];
const SQL: &str = "
CREATE TABLE native_incremental_epoch_owner_v2 (
 id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL CHECK(revision=2),
 source_anchor BLOB NOT NULL CHECK(length(source_anchor)=32), migration_sequence BLOB NOT NULL CHECK(length(migration_sequence)=8),
 migration_digest BLOB NOT NULL CHECK(length(migration_digest)=32), tip_binding BLOB NOT NULL CHECK(length(tip_binding)=32),
 prefix BLOB NOT NULL CHECK(length(prefix)>=4 AND length(prefix)<=1028 AND (length(prefix)-4)%32=0),
 generation BLOB NOT NULL CHECK(length(generation)=8), checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT;
CREATE TABLE native_incremental_epoch_edge_v2 (
 binding BLOB PRIMARY KEY CHECK(length(binding)=32), ordinal BLOB NOT NULL UNIQUE CHECK(length(ordinal)=8),
 predecessor BLOB CHECK(predecessor IS NULL OR length(predecessor)=32),
 prefix BLOB NOT NULL CHECK(length(prefix)>=4 AND length(prefix)<=1028 AND (length(prefix)-4)%32=0),
 checkpoint_head BLOB NOT NULL CHECK(length(checkpoint_head)=104), checkpoint_p BLOB NOT NULL CHECK(length(checkpoint_p)=32),
 checkpoint_sequence BLOB NOT NULL UNIQUE CHECK(length(checkpoint_sequence)=8), context_digest BLOB NOT NULL CHECK(length(context_digest)=32),
 evidence_kind INTEGER NOT NULL CHECK(evidence_kind IN(0,1)), evidence BLOB NOT NULL CHECK(length(evidence)>0 AND length(evidence)<=67108864),
 phase INTEGER NOT NULL CHECK(phase IN(0,1)), consumed_block BLOB UNIQUE CHECK(consumed_block IS NULL OR length(consumed_block)=32),
 consumed_p BLOB CHECK(consumed_p IS NULL OR length(consumed_p)=32), consumed_sequence BLOB UNIQUE CHECK(consumed_sequence IS NULL OR length(consumed_sequence)=8),
 checksum BLOB NOT NULL CHECK(length(checksum)=32),
 CHECK((phase=0 AND consumed_block IS NULL AND consumed_p IS NULL AND consumed_sequence IS NULL) OR (phase=1 AND consumed_block IS NOT NULL AND consumed_p IS NOT NULL AND consumed_sequence IS NOT NULL))) STRICT, WITHOUT ROWID;
CREATE TABLE native_incremental_epoch_p_context_v2 (
 block BLOB PRIMARY KEY CHECK(length(block)=32), p_digest BLOB NOT NULL CHECK(length(p_digest)=32), kind INTEGER NOT NULL CHECK(kind IN(0,1,2)),
 prefix BLOB NOT NULL CHECK(length(prefix)>=4 AND length(prefix)<=1028 AND (length(prefix)-4)%32=0),
 cutoff_head BLOB CHECK(cutoff_head IS NULL OR length(cutoff_head)=104), cutoff_p BLOB CHECK(cutoff_p IS NULL OR length(cutoff_p)=32),
 cutoff_sequence BLOB CHECK(cutoff_sequence IS NULL OR length(cutoff_sequence)=8), checksum BLOB NOT NULL CHECK(length(checksum)=32),
 CHECK((kind=2 AND cutoff_head IS NOT NULL AND cutoff_p IS NOT NULL AND cutoff_sequence IS NOT NULL) OR (kind IN(0,1) AND cutoff_head IS NULL AND cutoff_p IS NULL AND cutoff_sequence IS NULL))) STRICT, WITHOUT ROWID;
CREATE TABLE native_incremental_epoch_pre_handoff_v2 (
 checkpoint_block BLOB PRIMARY KEY CHECK(length(checkpoint_block)=32), p_digest BLOB NOT NULL CHECK(length(p_digest)=32),
 commit_sequence BLOB NOT NULL UNIQUE CHECK(length(commit_sequence)=8), checkpoint_head BLOB NOT NULL CHECK(length(checkpoint_head)=104),
 predecessor_edge BLOB NOT NULL UNIQUE CHECK(length(predecessor_edge)=32),
 prefix BLOB NOT NULL CHECK(length(prefix)>=4 AND length(prefix)<=1028 AND (length(prefix)-4)%32=0), context_digest BLOB NOT NULL CHECK(length(context_digest)=32),
 checkpoint_finality BLOB NOT NULL CHECK(length(checkpoint_finality)>0 AND length(checkpoint_finality)<=8388608),
 descriptor BLOB NOT NULL CHECK(length(descriptor)>0 AND length(descriptor)<=4096),
 next_epoch_commitment BLOB NOT NULL CHECK(length(next_epoch_commitment)>0 AND length(next_epoch_commitment)<=4096),
 new_validator_set BLOB NOT NULL CHECK(length(new_validator_set)>0 AND length(new_validator_set)<=1048576),
 new_parameters BLOB NOT NULL CHECK(length(new_parameters)>0 AND length(new_parameters)<=4096),
 strict_binding BLOB NOT NULL CHECK(length(strict_binding)=32), checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT, WITHOUT ROWID;
CREATE TABLE native_incremental_epoch_first_commit_v2 (
 block BLOB PRIMARY KEY CHECK(length(block)=32), edge BLOB NOT NULL UNIQUE CHECK(length(edge)=32),
 p_digest BLOB NOT NULL CHECK(length(p_digest)=32), sequence BLOB NOT NULL UNIQUE CHECK(length(sequence)=8), head BLOB NOT NULL CHECK(length(head)=104),
 proof BLOB NOT NULL CHECK(length(proof)>0 AND length(proof)<=8388608), proof_digest BLOB NOT NULL CHECK(length(proof_digest)=32), checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT, WITHOUT ROWID;
CREATE TABLE native_incremental_epoch_ordinary_commit_v2 (
 block BLOB PRIMARY KEY CHECK(length(block)=32), edge BLOB NOT NULL CHECK(length(edge)=32),
 p_digest BLOB NOT NULL CHECK(length(p_digest)=32), sequence BLOB NOT NULL UNIQUE CHECK(length(sequence)=8), head BLOB NOT NULL CHECK(length(head)=104),
 proof BLOB NOT NULL CHECK(length(proof)>0 AND length(proof)<=8388608), proof_digest BLOB NOT NULL CHECK(length(proof_digest)=32), checksum BLOB NOT NULL CHECK(length(checksum)=32)) STRICT, WITHOUT ROWID;
";

fn objects(c: &Connection) -> Result<Vec<(String, String, String)>> {
    let mut q = c.prepare("SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name LIMIT 65")?;
    let mut rows = q.query([])?;
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        ensure!(result.len() < 64, "schema11 schema inventory capacity");
        let text = |i, cap| -> Result<String> {
            match row.get_ref(i)? {
                ValueRef::Text(bytes) if bytes.len() <= cap => {
                    Ok(std::str::from_utf8(bytes)?.to_owned())
                }
                _ => anyhow::bail!("schema11 schema field type/capacity"),
            }
        };
        result.push((
            text(0, 16)?,
            text(1, 128)?,
            normalize_sql_v0(&text(2, 16384)?),
        ));
    }
    Ok(result)
}
pub(in crate::durable) fn verify_schema(c: &Connection) -> DurableResult<()> {
    (|| -> Result<()> {
        ensure!(
            epoch_durable::schema_version(c)? == SCHEMA_VERSION,
            "schema11 required"
        );
        let mut reference = Connection::open_in_memory()?;
        initialize_schema_v0(&reference)?;
        let tx = reference.transaction()?;
        ni::install_incremental_schema_v1(&tx)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute_batch(replay::SCHEMA)?;
        tx.execute_batch(super::SQL)?;
        tx.execute_batch(commit::SQL)?;
        tx.execute_batch(SQL)?;
        tx.commit()?;
        ensure!(
            objects(c)? == objects(&reference)?,
            "schema11 closed schema"
        );
        Ok(())
    })()
    .map_err(fail)
}

fn blob(bytes: impl AsRef<[u8]>) -> Value {
    Value::Blob(bytes.as_ref().to_vec())
}
fn number_value(n: u64) -> Value {
    blob(n.to_be_bytes())
}
fn prefix(bindings: &[[u8; 32]]) -> Result<Vec<u8>> {
    ensure!(bindings.len() <= 32, "schema11 prefix capacity");
    let unique: BTreeSet<_> = bindings.iter().collect();
    ensure!(
        unique.len() == bindings.len() && !unique.contains(&[0; 32]),
        "schema11 prefix identity"
    );
    let mut bytes = u32::try_from(bindings.len())?.to_be_bytes().to_vec();
    for binding in bindings {
        bytes.extend(binding);
    }
    Ok(bytes)
}
// A row is a deterministic projection of strictly audited original records.
// The SQL reader compares ValueRef directly; hostile BLOBs are never cloned.
struct ProjectedRow {
    table: usize,
    values: Vec<Value>,
}
impl ProjectedRow {
    fn new(table: usize, values: Vec<Value>) -> Self {
        Self { table, values }
    }
    fn finish(
        mut self,
        config: &NativeApplicationConfigV0,
        anchor: [u8; 32],
        hashed: &[usize],
        nullable: &[usize],
        extra: &[&[u8]],
    ) -> Result<Self> {
        let domains = [
            "trnm.native-application.incremental-epoch-owner.v2",
            "trnm.native-application.incremental-epoch-edge.v2",
            "trnm.native-application.incremental-epoch-p-context.v2",
            "trnm.native-application.incremental-epoch-pre-handoff.v2",
            "trnm.native-application.incremental-epoch-first-commit.v2",
            "trnm.native-application.incremental-epoch-ordinary-commit.v2",
        ];
        let mut fields = vec![config.store_id.to_vec(), anchor.to_vec()];
        for (index, value) in self.values.iter().enumerate() {
            let mut field = if nullable.contains(&index) {
                vec![u8::from(!matches!(value, Value::Null))]
            } else {
                Vec::new()
            };
            match value {
                Value::Integer(n) => field.extend(n.to_be_bytes()),
                Value::Blob(bytes) if hashed.contains(&index) => field.extend(sha256_v0(bytes)),
                Value::Blob(bytes) => field.extend(bytes),
                Value::Null if nullable.contains(&index) => (),
                _ => anyhow::bail!("schema11 projection field type"),
            }
            fields.push(field);
        }
        let mut refs: Vec<_> = fields.iter().map(Vec::as_slice).collect();
        refs.extend_from_slice(extra);
        self.values
            .push(blob(hash_domain(domains[self.table], &refs)));
        Ok(self)
    }
    fn insert(&self, tx: &rusqlite::Transaction<'_>) -> Result<()> {
        let placeholders = vec!["?"; self.values.len()].join(",");
        ensure!(
            tx.execute(
                &format!("INSERT INTO {} VALUES({placeholders})", TABLES[self.table]),
                rusqlite::params_from_iter(self.values.iter())
            )? == 1,
            "schema11 projection insert"
        );
        Ok(())
    }
}
struct Projection {
    rows: Vec<ProjectedRow>,
    pin: [u8; 32],
    old_pin: [u8; 32],
    current: Current,
}
struct Current {
    base: Owner,
    edge: EdgeRow,
    first: commit::Commit,
    first_p: EpochP,
    ordinary: BTreeMap<[u8; 32], P>,
    epochs: BTreeMap<[u8; 32], EpochP>,
    runtime: trnm_consensus_crypto::StrictEpochRuntimeContextV1,
    migration_sequence: u64,
    generation: u64,
    pre_handoff: Option<progress::pre_handoff::PreHandoff>,
    pending: Option<progress::pre_handoff::attachment::Pending>,
}
struct RetainedContextRef<'a> {
    runtime: &'a trnm_consensus_crypto::StrictEpochRuntimeContextV1,
    binding: [u8; 32],
    prefix: Vec<[u8; 32]>,
}
impl Current {
    fn context_for(&self, h: &BlockHeader) -> Result<RetainedContextRef<'_>> {
        if h.epoch() == self.runtime.activation().new_validator_set().epoch() {
            Ok(RetainedContextRef {
                runtime: &self.runtime,
                binding: self.edge.binding,
                prefix: vec![self.edge.binding],
            })
        } else {
            let pending = self
                .pending
                .as_ref()
                .context("schema11 P epoch lacks installed context")?;
            ensure!(
                h.epoch() == pending.runtime().activation().new_validator_set().epoch(),
                "schema11 P epoch outside retained prefix"
            );
            Ok(RetainedContextRef {
                runtime: pending.runtime(),
                binding: pending.binding(),
                prefix: self.owner_prefix(),
            })
        }
    }
    fn owner_prefix(&self) -> Vec<[u8; 32]> {
        let mut bindings = vec![self.edge.binding];
        if let Some(pending) = &self.pending {
            bindings.push(pending.binding());
        }
        bindings
    }
}

fn bounded_blocks(tx: &rusqlite::Transaction<'_>, table: &str) -> Result<Vec<[u8; 32]>> {
    let mut q = tx.prepare(&format!(
        "SELECT block FROM {table} ORDER BY block LIMIT 129"
    ))?;
    let mut rows = q.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        ensure!(out.len() < MAX_PREPARED, "schema11 source row capacity");
        out.push(fixed(row_blob(row, 0, 32, 32)?)?);
    }
    Ok(out)
}
fn replay_keys(transactions: &[Vec<u8>]) -> Result<Vec<KeyHash>> {
    transactions
        .iter()
        .map(|raw| -> Result<_> {
            let envelope: trnm_finality_types::SignedCommandEnvelopeV1 =
                serde_json::from_slice(raw)?;
            Ok([
                replay::command_key(&envelope.command_id)?,
                replay::nonce_key(&envelope.signer_id, envelope.nonce)?,
            ])
        })
        .collect::<Result<Vec<_>>>()
        .map(|keys| keys.into_iter().flatten().collect())
}
fn ordinary_replay_parent(
    p: &P,
    ordinary: &BTreeMap<[u8; 32], P>,
    first: &EpochP,
    epochs: &[EpochP],
) -> Result<(ReplayHead, Vec<ReplayDelta>)> {
    let mut current = p;
    let mut suffix = Vec::new();
    let mut bytes = 0usize;
    loop {
        if current.parent == first.target()? {
            ensure!(
                current.parent_p == Some(first.digest)
                    && current.replay_parent == ReplayDelta::decode(&first.replay_delta)?.head,
                "schema11 first replay ancestry"
            );
            return Ok((ReplayDelta::decode(&first.replay_delta)?.head, suffix));
        }
        if let Some(parent) = epochs
            .iter()
            .find(|p| p.block == *current.parent.block_id().as_bytes())
        {
            let delta = ReplayDelta::decode(&parent.replay_delta)?;
            ensure!(
                parent.edge != first.edge
                    && current.parent == parent.target()?
                    && current.parent_p == Some(parent.digest)
                    && parent.sequence < current.sequence
                    && current.replay_parent == delta.head,
                "schema11 pending first replay ancestry"
            );
            bytes = bytes
                .checked_add(parent.replay_delta.len())
                .context("schema11 first replay overflow")?;
            ensure!(
                suffix.len() < 8 && bytes <= 64 * 1024 * 1024,
                "schema11 pending first replay bound"
            );
            suffix.push(delta);
            return Ok((parent.replay_parent, suffix));
        }
        let parent = ordinary
            .get(current.parent.block_id().as_bytes())
            .context("schema11 prepared parent missing")?;
        ensure!(
            parent.target()? == current.parent
                && current.parent_p == Some(parent.digest)
                && parent.sequence < current.sequence
                && current.replay_parent == parent.replay()?.head,
            "schema11 prepared parent splice"
        );
        if parent.status == 1 {
            return Ok((parent.replay()?.head, suffix));
        }
        let delta = parent.replay()?;
        bytes = bytes
            .checked_add(parent.replay_delta.len())
            .context("schema11 replay size overflow")?;
        ensure!(
            suffix.len() < 8 && bytes <= 64 * 1024 * 1024,
            "schema11 pending replay bound"
        );
        suffix.push(delta);
        current = parent;
    }
}

fn screen_inventory(tx: &rusqlite::Transaction<'_>, schema: u64) -> Result<()> {
    // Screen both native P inventories before the legacy owner walks a single
    // committed artifact. The frozen legacy audit checks these totals later.
    for table in ["native_incremental_p_v1", "native_incremental_epoch_p_v1"] {
        let (count, bytes, invalid): (u64, u64, u64) = tx.query_row(
            &format!("SELECT count(*),coalesce(sum(CASE WHEN typeof(artifact)='blob' AND typeof(header)='blob' AND typeof(replay_delta)='blob' AND typeof(lifecycle)='blob' THEN length(artifact)+length(header)+length(replay_delta)+length(lifecycle) ELSE 0 END),0),coalesce(sum(CASE WHEN typeof(artifact)!='blob' OR length(artifact)=0 OR length(artifact)>16777216 OR typeof(header)!='blob' OR length(header)=0 OR length(header)>4096 OR typeof(replay_delta)!='blob' OR length(replay_delta)=0 OR length(replay_delta)>16777216 OR typeof(lifecycle)!='blob' OR length(lifecycle)>1048576 THEN 1 ELSE 0 END),0) FROM {table}"),
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        )?;
        ensure!(
            count <= MAX_PREPARED as u64 && bytes <= MAX_P_BYTES as u64 && invalid == 0,
            "schema11 original P inventory capacity/type"
        );
    }
    // Screen legacy proof budgets before any proof allocation. Schema7 allowed
    // larger per-record bytes; migration does not grandfather them into v2.
    for table in [
        "native_incremental_epoch_commit_v1",
        "native_incremental_epoch_descendant_commit_v1",
    ] {
        let (count, bytes, invalid): (u64, u64, u64) = tx.query_row(&format!("SELECT count(*),coalesce(sum(CASE WHEN typeof(proof)='blob' THEN length(proof) ELSE 0 END),0),coalesce(sum(CASE WHEN typeof(proof)!='blob' OR length(proof)=0 OR length(proof)>8388608 THEN 1 ELSE 0 END),0) FROM {table}"), [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        ensure!(
            count <= MAX_PREPARED as u64
                && bytes <= MAX_EPOCH_EVIDENCE_BYTES_V1 as u64
                && invalid == 0,
            "schema11 original proof capacity/type"
        );
    }
    if schema == SCHEMA_VERSION {
        progress::pre_handoff::attachment::screen(tx)?;
        progress::pre_handoff::screen(tx)?;
        for table in [
            "native_incremental_epoch_first_commit_v2",
            "native_incremental_epoch_ordinary_commit_v2",
        ] {
            let (count,bytes,invalid):(u64,u64,u64)=tx.query_row(&format!("SELECT count(*),coalesce(sum(CASE WHEN typeof(proof)='blob' THEN length(proof) ELSE 0 END),0),coalesce(sum(CASE WHEN typeof(proof)!='blob' OR length(proof)=0 OR length(proof)>8388608 THEN 1 ELSE 0 END),0) FROM {table}"),[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            ensure!(
                count <= MAX_PREPARED as u64
                    && bytes <= MAX_EPOCH_EVIDENCE_BYTES_V1 as u64
                    && invalid == 0,
                "schema11 projected proof capacity/type"
            );
        }
    }
    Ok(())
}
fn reserve_p_capacity(
    tx: &rusqlite::Transaction<'_>,
    artifact: &[u8],
    header: &[u8],
    replay: &[u8],
    lifecycle: &[u8],
) -> Result<()> {
    ensure!(
        !artifact.is_empty()
            && artifact.len() <= 16 * 1024 * 1024
            && !header.is_empty()
            && header.len() <= 4096
            && !replay.is_empty()
            && replay.len() <= 16 * 1024 * 1024
            && lifecycle.len() <= 1024 * 1024,
        "schema11 proposed P field capacity"
    );
    let (count,bytes):(usize,usize)=tx.query_row("SELECT count(*),coalesce(sum(length(artifact)+length(header)+length(replay_delta)+length(lifecycle)),0) FROM native_incremental_p_v1",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
    let incoming = artifact.len() + header.len() + replay.len() + lifecycle.len();
    ensure!(
        count < MAX_PREPARED
            && bytes
                .checked_add(incoming)
                .is_some_and(|sum| sum <= MAX_P_BYTES),
        "schema11 prospective P capacity"
    );
    Ok(())
}

fn projection(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    m: &MetadataV0,
) -> Result<Projection> {
    projection_with_budget(
        tx,
        config,
        m,
        &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
    )
}
fn projection_with_budget(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    m: &MetadataV0,
    budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
) -> Result<Projection> {
    let schema = epoch_durable::schema_version(tx)?;
    ensure!(
        matches!(schema, COMMIT_SCHEMA_VERSION | SCHEMA_VERSION),
        "schema11 exact migration source"
    );
    screen_inventory(tx, schema)?;
    let migration_sequence = if schema == SCHEMA_VERSION {
        number(tx.query_row(
            "SELECT migration_sequence FROM native_incremental_epoch_owner_v2 WHERE id=1",
            [],
            |r| row_blob(r, 0, 8, 8),
        )?)?
    } else {
        m.durable_sequence
    };
    let (base, edge, audited) = if schema == SCHEMA_VERSION {
        // Original source facts do not confer current ownership. The complete
        // v2 current ledger below independently closes head and sequence.
        audit_source_owner(tx, config, m, budget)?
    } else {
        audit_owner_with_policy(tx, config, m, OwnerAuditPolicy::MigrationSource, budget)?
    };
    let coordinates = audited.coordinates(edge.binding)?;
    ni::require_absent_incremental_seals_v1(tx, coordinates)?;
    let seal_pins: u64 = tx.query_row(
        "SELECT count(*) FROM ni_pin WHERE version>?1 AND version<?2",
        params![
            coordinates.checkpoint_version.to_be_bytes().as_slice(),
            coordinates.first_version.to_be_bytes().as_slice()
        ],
        |r| r.get(0),
    )?;
    ensure!(seal_pins == 0, "schema11 seal has a sparse root pin");
    validate_source_replay(tx, config, &base)?;
    let first = commit::load(tx)?.context("schema11 requires consumed original edge")?;
    let evidence = EpochRecoveryEvidenceV1::decode(&edge.evidence)?;
    let (set, parameters) = descendant::context(&evidence)?;
    let geometry = trnm_consensus_types::EpochGeometryV0::new(set.epoch(), &parameters)
        .map_err(|e| anyhow::anyhow!("schema11 geometry: {e:?}"))?;
    ensure!(
        if schema == COMMIT_SCHEMA_VERSION {
            m.head.height().get() < geometry.checkpoint_height().get()
        } else {
            m.head.height().get() <= geometry.checkpoint_height().get()
        },
        "schema11 migration/current checkpoint boundary"
    );
    let first_p =
        commit::audit_record_shape(tx, config, &edge, &base.source, &audited.activation, &first)?;
    ensure!(
        first.sequence <= migration_sequence && migration_sequence <= m.durable_sequence,
        "schema11 immutable migration sequence"
    );
    // The already strict owner audit establishes terminal/active configuration;
    // use the original signed activation bytes for validating retained P forks.
    let epoch_context = EpochPContext {
        parent: &base.source,
        checkpoint_sequence: edge.sequence,
        binding: edge.binding,
        terminal: audited
            .activation
            .authorization_kernel()
            .terminal_old_header(),
        set: &set,
        parameters: &parameters,
    };
    let mut epochs = Vec::new();
    let mut ordinary = BTreeMap::new();
    let mut blocks = BTreeSet::new();
    let mut sequences = BTreeSet::new();
    for block in bounded_blocks(tx, "native_incremental_epoch_p_v1")? {
        let p = load_epoch_p(tx, block)?.context("schema11 epoch P missing")?;
        if p.edge == edge.binding {
            p.validate_context(config, &epoch_context)?;
        } else {
            ensure!(schema == SCHEMA_VERSION, "successor P requires schema11");
            // The original source does not authorize successor execution. Its
            // context is checked below only after strict successor attachment.
        }
        p.validate_storage(tx)?;
        ensure!(
            p.sequence > base.source_sequence
                && p.sequence <= m.durable_sequence
                && sequences.insert(p.sequence)
                && blocks.insert(p.block),
            "schema11 epoch sequence/block collision"
        );
        let replay = ReplayReader::new(tx, Some(p.replay_parent), &[])?;
        ensure!(
            (p.edge != edge.binding
                || p.replay_parent
                    == (ReplayHead {
                        version: 0,
                        root: base.source_replay
                    }))
                && replay
                    .append(replay_keys(
                        p.executed()?.request().preview().transactions()
                    )?)?
                    .encode()?
                    == p.replay_delta,
            "schema11 epoch replay substitution"
        );
        let reader = ni::open_incremental_reader_v1(
            tx,
            &namespace(config),
            ni::IncrementalParentV1::Prepared(p.storage_artifact),
        )?;
        ensure!(
            reader.version() == p.target()?.height().get()
                && reader.root().0 == *p.target()?.state_root().as_bytes(),
            "schema11 epoch sparse target"
        );
        let _ = reader.verified_live_values_v1()?;
        epochs.push(p);
    }
    for block in bounded_blocks(tx, "native_incremental_p_v1")? {
        let p = load_p(tx, block)?.context("schema11 ordinary P missing")?;
        if header(&p.header)?.epoch() != set.epoch() {
            ensure!(
                schema == SCHEMA_VERSION && p.status == 0,
                "schema11 successor ordinary preparation only"
            );
        } else if schema == SCHEMA_VERSION
            && header(&p.header)?.block_kind() == trnm_consensus_types::BlockKind::EpochCheckpoint
        {
            p.validate_context_kind(
                config,
                &set,
                &parameters,
                trnm_consensus_types::BlockKind::EpochCheckpoint,
            )?;
            ensure!(
                p.parent_p.is_some()
                    && p.target()?.height().get() == geometry.checkpoint_height().get(),
                "schema11 kind2 exact geometry"
            );
        } else {
            descendant::validate_p(&p, config, &set, &parameters, base.source.height().get())?;
        }
        descendant::validate_storage_p(tx, &p)?;
        ensure!(
            p.sequence > first_p.sequence
                && p.sequence <= m.durable_sequence
                && sequences.insert(p.sequence)
                && blocks.insert(p.block),
            "schema11 ordinary sequence/block collision"
        );
        if let Some(sequence) = p.commit_sequence {
            ensure!(
                sequence > p.sequence
                    && sequence <= m.durable_sequence
                    && sequences.insert(sequence),
                "schema11 ordinary commit sequence collision"
            );
        }
        ordinary.insert(block, p);
    }
    ensure!(
        first.sequence <= m.durable_sequence && sequences.insert(first.sequence),
        "schema11 first commit sequence collision"
    );
    for p in ordinary.values() {
        let (parent, suffix) = ordinary_replay_parent(p, &ordinary, &first_p, &epochs)?;
        ensure!(
            ReplayReader::new(tx, Some(parent), &suffix)?
                .append(replay_keys(p.executed()?.request().transactions())?)?
                .encode()?
                == p.replay_delta,
            "schema11 ordinary replay substitution"
        );
        let reader = ni::open_incremental_reader_v1(
            tx,
            &namespace(config),
            ni::IncrementalParentV1::Prepared(p.storage_artifact),
        )?;
        ensure!(
            reader.version() == p.target()?.height().get()
                && reader.root().0 == *p.target()?.state_root().as_bytes(),
            "schema11 ordinary sparse target"
        );
        let _ = reader.verified_live_values_v1()?;
    }
    let (ni_p, ni_edges): (usize, usize) = tx.query_row(
        "SELECT (SELECT count(*) FROM ni_prepared),(SELECT count(*) FROM ni_epoch_edge)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(
        ni_p == epochs.len() + ordinary.len(),
        "schema11 sparse/native inventory differs"
    );
    let original_records = bounded_blocks(tx, "native_incremental_epoch_descendant_commit_v1")?
        .into_iter()
        .map(|block| {
            descendant::load_commit(tx, block)?.context("schema11 ordinary original proof missing")
        })
        .collect::<Result<Vec<_>>>()?;
    for r in &original_records {
        ensure!(
            r.sequence <= migration_sequence
                && r.checksum == descendant::commit_digest(config, &edge, r),
            "schema11 original record changed"
        );
    }
    let mut records = if schema == SCHEMA_VERSION {
        load_ordinary_records(tx)?
    } else {
        original_records.clone()
    };
    let pre_handoff = if schema == SCHEMA_VERSION {
        progress::pre_handoff::load(tx)?
    } else {
        None
    };
    if let Some(tail) = &pre_handoff {
        records.push(tail.record.clone());
    }
    let runtime =
        trnm_consensus_crypto::StrictEpochRuntimeContextV1::from_activation_v1(audited.activation)
            .map_err(|e| anyhow::anyhow!("schema11 strict runtime: {e}"))?;
    if schema == SCHEMA_VERSION {
        let verified = runtime
            .decode_verify_finality_v1(
                &first.proof,
                runtime
                    .activation()
                    .authorization_kernel()
                    .terminal_old_header()
                    .timestamp_ms(),
                budget,
            )
            .map_err(|e| anyhow::anyhow!("schema11 first finality: {e}"))?;
        ensure!(
            verified.finalized_block().header() == &header(&first_p.header)?,
            "schema11 first finality header"
        );
    }
    let mut ordered: Vec<_> = records.iter().collect();
    ordered.sort_by_key(|r| r.head.height().get());
    let mut previous_head = first.head.clone();
    let mut previous_digest = first.p_digest;
    let mut previous_header = header(&first_p.header)?;
    let mut previous_sequence = first.sequence;
    let mut previous_replay = ReplayDelta::decode(&first_p.replay_delta)?.head;
    let mut generation = 0u64;
    for r in ordered {
        let p = ordinary
            .get(&r.block)
            .context("schema11 committed P absent")?;
        ensure!(
            p.status == 1
                && p.target()? == r.head
                && p.digest == r.p_digest
                && p.commit_sequence == Some(r.sequence)
                && r.sequence > p.sequence
                && r.sequence > previous_sequence
                && p.parent == previous_head
                && p.parent_p == Some(previous_digest)
                && p.replay_parent == previous_replay,
            "schema11 current committed ancestry"
        );
        if let Some(original) = original_records
            .iter()
            .find(|original| original.block == r.block)
        {
            ensure!(
                original.p_digest == r.p_digest
                    && original.sequence == r.sequence
                    && original.head == r.head
                    && original.proof == r.proof,
                "schema11 immutable source proof changed"
            );
        } else {
            ensure!(
                r.sequence > migration_sequence,
                "schema11 non-source commit below migration"
            );
            generation = generation
                .checked_add(1)
                .context("schema11 generation exhausted")?;
        }
        if schema == SCHEMA_VERSION
            && pre_handoff
                .as_ref()
                .is_none_or(|tail| tail.record.block != r.block)
        {
            ensure!(
                header(&p.header)?.block_kind() == trnm_consensus_types::BlockKind::Regular,
                "schema11 ordinary ledger kind"
            );
            let verified = runtime
                .decode_verify_finality_v1(&r.proof, previous_header.timestamp_ms(), budget)
                .map_err(|e| anyhow::anyhow!("schema11 ordinary finality: {e}"))?;
            ensure!(
                verified.finalized_block().header() == &header(&p.header)?,
                "schema11 ordinary complete finality header"
            );
        }
        previous_head = r.head.clone();
        previous_digest = p.digest;
        previous_header = header(&p.header)?;
        previous_sequence = r.sequence;
        previous_replay = p.replay()?.head;
    }
    ensure!(
        original_records
            .iter()
            .all(|r| records.iter().any(|v| v.block == r.block))
            && ordinary.values().filter(|p| p.status == 1).count() == records.len()
            && previous_head == m.head
            && previous_sequence == base.commit_sequence
            && previous_replay == base.replay
            && sequences.last().copied() == Some(m.durable_sequence),
        "schema11 closed current inventory"
    );
    let _ = ReplayReader::new(tx, Some(base.replay), &[])?;
    let pre_handoff_row = if let Some(tail) = &pre_handoff {
        ensure!(
            tail.record.head == m.head,
            "schema11 unattached checkpoint is not current tail"
        );
        Some(progress::pre_handoff::audit(
            tx, config, &base, &edge, &first_p, &ordinary, &runtime, tail, budget,
        )?)
    } else {
        None
    };
    let pending = if schema == SCHEMA_VERSION {
        progress::pre_handoff::attachment::audit_pending(
            tx,
            config,
            &base,
            &edge,
            &first_p,
            &ordinary,
            &runtime,
            pre_handoff.as_ref(),
            &m.head,
            budget,
        )?
    } else {
        None
    };
    let successor_epochs: Vec<_> = epochs.iter().filter(|p| p.edge != edge.binding).collect();
    let staged_successor = !successor_epochs.is_empty();
    ensure!(
        ni_edges == 1 + usize::from(staged_successor),
        "schema11 exact sparse edge inventory"
    );
    if let Some(installed) = &pending {
        for p in successor_epochs {
            installed.audit_prepared(tx, config, &base, p)?;
        }
        for p in ordinary
            .values()
            .filter(|p| header(&p.header).is_ok_and(|h| h.epoch() != set.epoch()))
        {
            installed.audit_ordinary(config, p)?;
        }
    } else {
        ensure!(
            !staged_successor
                && ordinary
                    .values()
                    .all(|p| header(&p.header).is_ok_and(|h| h.epoch() == set.epoch())),
            "schema11 successor P without strict installed edge"
        );
    }
    let mut owner_prefix = vec![edge.binding];
    if let Some(installed) = &pending {
        owner_prefix.push(installed.binding());
        generation = generation
            .checked_add(1)
            .context("schema11 attachment generation exhausted")?;
    }
    let mut record_digests = vec![edge.checksum, first.checksum];
    record_digests.extend(original_records.iter().map(|r| r.checksum));
    record_digests.sort();
    let mut fields = vec![
        base.anchor.to_vec(),
        migration_sequence.to_be_bytes().to_vec(),
    ];
    fields.extend(record_digests.iter().map(|d| d.to_vec()));
    let pin = hash_domain(
        "trnm.native-application.incremental-epoch-migration.v2",
        &fields.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    );
    let prefix = prefix(&[edge.binding])?;
    let empty = 0u32.to_be_bytes();
    let context = hash_domain(
        "trnm.native-application.incremental-epoch-context.v2",
        &[
            &config.store_id,
            &base.anchor,
            &edge.checkpoint_p,
            &head_bytes(&base.source),
            &edge.sequence.to_be_bytes(),
            &empty,
            &sha256_v0(&evidence.old_set),
            &sha256_v0(&evidence.old_parameters),
            &sha256_v0(&evidence.cutoff_finality),
        ],
    );
    let mut rows = vec![
        ProjectedRow::new(
            0,
            vec![
                Value::Integer(1),
                Value::Integer(2),
                blob(base.anchor),
                number_value(migration_sequence),
                blob(pin),
                blob(*owner_prefix.last().context("schema11 empty owner prefix")?),
                blob(self::prefix(&owner_prefix)?),
                number_value(generation),
            ],
        )
        .finish(
            config,
            base.anchor,
            &[],
            &[],
            &[&base.checksum, &head_bytes(&m.head)],
        )?,
        ProjectedRow::new(
            1,
            vec![
                blob(edge.binding),
                number_value(0),
                Value::Null,
                blob(empty),
                blob(head_bytes(&base.source)),
                blob(edge.checkpoint_p),
                number_value(edge.sequence),
                blob(context),
                Value::Integer(0),
                blob(&edge.evidence),
                Value::Integer(1),
                blob(first.block),
                blob(first.p_digest),
                number_value(first.sequence),
            ],
        )
        .finish(config, base.anchor, &[9], &[2, 11, 12, 13], &[])?,
    ];
    for p in &epochs {
        rows.push(
            ProjectedRow::new(
                2,
                vec![
                    blob(p.block),
                    blob(p.digest),
                    Value::Integer(1),
                    blob(if p.edge == edge.binding {
                        prefix.clone()
                    } else {
                        self::prefix(&owner_prefix)?
                    }),
                    Value::Null,
                    Value::Null,
                    Value::Null,
                ],
            )
            .finish(config, base.anchor, &[], &[4, 5, 6], &[])?,
        );
    }
    for p in ordinary.values() {
        rows.push(
            if header(&p.header)?.block_kind() == trnm_consensus_types::BlockKind::EpochCheckpoint {
                progress::checkpoint::checkpoint_context(
                    tx,
                    config,
                    &base,
                    &edge,
                    &ordinary,
                    &set,
                    &parameters,
                    p,
                )?
            } else {
                ProjectedRow::new(
                    2,
                    vec![
                        blob(p.block),
                        blob(p.digest),
                        Value::Integer(0),
                        blob(if header(&p.header)?.epoch() == set.epoch() {
                            prefix.clone()
                        } else {
                            self::prefix(&owner_prefix)?
                        }),
                        Value::Null,
                        Value::Null,
                        Value::Null,
                    ],
                )
                .finish(config, base.anchor, &[], &[4, 5, 6], &[])?
            },
        );
    }
    for (table, r) in std::iter::once((4, &first)).chain(
        records
            .iter()
            .filter(|r| {
                pre_handoff
                    .as_ref()
                    .is_none_or(|tail| tail.record.block != r.block)
            })
            .map(|r| (5, r)),
    ) {
        ensure!(
            !r.proof.is_empty() && r.proof.len() <= MAX_PROOF,
            "schema11 proof bound"
        );
        rows.push(
            ProjectedRow::new(
                table,
                vec![
                    blob(r.block),
                    blob(edge.binding),
                    blob(r.p_digest),
                    number_value(r.sequence),
                    blob(head_bytes(&r.head)),
                    blob(&r.proof),
                    blob(sha256_v0(&r.proof)),
                ],
            )
            .finish(config, base.anchor, &[5], &[], &[])?,
        );
    }
    if let Some(row) = pre_handoff_row {
        rows.push(row);
    }
    if let Some(installed) = &pending {
        rows.push(installed.row(config, base.anchor)?);
    }
    let projection = Projection {
        rows,
        pin,
        old_pin: edge.checksum,
        current: Current {
            base,
            edge,
            first,
            first_p,
            ordinary,
            epochs: epochs.into_iter().map(|p| (p.block, p)).collect(),
            runtime,
            migration_sequence,
            generation,
            pre_handoff,
            pending,
        },
    };
    if schema == SCHEMA_VERSION {
        progress::checkpoint::audit_sidecars(tx, config, m, &projection, budget)?;
    }
    Ok(projection)
}

fn load_ordinary_records(tx: &rusqlite::Transaction<'_>) -> Result<Vec<commit::Commit>> {
    let (count, bytes, invalid): (u64,u64,u64) = tx.query_row("SELECT count(*),coalesce(sum(length(proof)),0),coalesce(sum(CASE WHEN typeof(proof)!='blob' OR length(proof)=0 OR length(proof)>8388608 THEN 1 ELSE 0 END),0) FROM native_incremental_epoch_ordinary_commit_v2", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    ensure!(
        count <= MAX_PREPARED as u64 && bytes <= MAX_EPOCH_EVIDENCE_BYTES_V1 as u64 && invalid == 0,
        "schema11 current proof capacity"
    );
    let mut query = tx.prepare("SELECT block,p_digest,sequence,head,proof,checksum FROM native_incremental_epoch_ordinary_commit_v2 ORDER BY block LIMIT 129")?;
    let mut rows = query.query([])?;
    let mut result = Vec::new();
    while let Some(r) = rows.next()? {
        result.push(commit::Commit {
            block: fixed(row_blob(r, 0, 32, 32)?)?,
            p_digest: fixed(row_blob(r, 1, 32, 32)?)?,
            sequence: number(row_blob(r, 2, 8, 8)?)?,
            head: decode_head(&row_blob(r, 3, 104, 104)?)?,
            proof: row_blob(r, 4, 1, MAX_PROOF)?,
            checksum: fixed(row_blob(r, 5, 32, 32)?)?,
        });
    }
    Ok(result)
}

fn compare_projection(tx: &rusqlite::Transaction<'_>, projection: &Projection) -> Result<()> {
    for (table, name) in TABLES.iter().enumerate() {
        let expected: Vec<_> = projection
            .rows
            .iter()
            .filter(|r| r.table == table)
            .collect();
        let count: u64 = tx.query_row(&format!("SELECT count(*) FROM {name}"), [], |r| r.get(0))?;
        ensure!(
            count == expected.len() as u64,
            "schema11 projection row count differs: {name}"
        );
        for row in expected {
            let pk = if table == 0 {
                "id"
            } else if table == 1 {
                "binding"
            } else if table == 3 {
                "checkpoint_block"
            } else {
                "block"
            };
            let mut statement = tx.prepare(&format!("SELECT * FROM {name} WHERE {pk}=?1"))?;
            let mut actual = statement.query([&row.values[0]])?;
            let actual_row = actual.next()?.context("schema11 projection row missing")?;
            for (column, value) in row.values.iter().enumerate() {
                let equal = match (actual_row.get_ref(column)?, value) {
                    (ValueRef::Null, Value::Null) => true,
                    (ValueRef::Integer(a), Value::Integer(b)) => a == *b,
                    (ValueRef::Blob(a), Value::Blob(b)) => a == b,
                    _ => false,
                };
                ensure!(
                    equal,
                    "schema11 immutable migration projection differs: {name}:{column}"
                );
            }
            ensure!(
                actual.next()?.is_none(),
                "schema11 duplicate projection row"
            );
        }
    }
    Ok(())
}
pub(in crate::durable) fn audit_anchor(
    c: &Connection,
    config: &NativeApplicationConfigV0,
    m: &MetadataV0,
) -> DurableResult<[u8; 32]> {
    (|| -> Result<_> {
        verify_schema(c)?;
        let tx = c.unchecked_transaction()?;
        let projection = projection(&tx, config, m)?;
        compare_projection(&tx, &projection)?;
        Ok(projection.pin)
    })()
    .map_err(fail)
}
impl DurableNativeApplicationV0 {
    /// Explicitly migrate a consumed schema7 edge and its complete original
    /// sparse execution/proof inventory. This changes no application head or
    /// sequence and grants no activation, finality, checkpoint or signing power.
    /// A schema11 retry audits its current inventory against the same immutable seed.
    pub fn upgrade_incremental_multi_epoch_schema_v2(&self) -> Result<()> {
        self.upgrade_incremental_multi_epoch_schema_with_budget_v2(
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
        )
    }
    // Shared operation kernel also lets the genuine source7 regression prove
    // that readback admission fails before the schema CAS or any table creation.
    pub(in crate::durable) fn upgrade_incremental_multi_epoch_schema_with_budget_v2(
        &self,
        budget: &mut trnm_consensus_types::Cev0AdmissionBudgetV0,
    ) -> Result<()> {
        let starting_work = budget.signature_work();
        let _guard = self.lock_operation()?;
        let mut c = open_writable_connection_v0(&self.path)?;
        verify_schema_v0(&c)?;
        let schema = epoch_durable::schema_version(&c)?;
        ensure!(
            matches!(schema, COMMIT_SCHEMA_VERSION | SCHEMA_VERSION),
            "schema11 migration requires physical schema7 or exact retry"
        );
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let m = load_metadata_v0(&tx, &self.config)?;
        let expected = projection_with_budget(&tx, &self.config, &m, budget)?;
        let pinned = *self
            .incremental_migration_pin
            .lock()
            .map_err(|_| anyhow::anyhow!("schema11 migration pin lock"))?;
        ensure!(
            pinned == Some(expected.old_pin)
                || (schema == SCHEMA_VERSION && pinned == Some(expected.pin)),
            "schema11 migration owner pin changed"
        );
        // The source7 audit repeats activation checks for each legacy proof;
        // its measured work bounds the schema11 prefix-once fresh audit. For
        // schema11 retry this is the identical inventory and exact same cost.
        progress::require_readback_budget(budget, budget.signature_work() - starting_work)?;
        if schema == COMMIT_SCHEMA_VERSION {
            tx.execute_batch(SQL)?;
            for row in &expected.rows {
                row.insert(&tx)?;
            }
            ensure!(tx.execute("UPDATE native_application_metadata_v0 SET schema_version=?1 WHERE singleton=1 AND schema_version=?2 AND durable_sequence=?3", params![SCHEMA_VERSION.to_be_bytes().as_slice(),COMMIT_SCHEMA_VERSION.to_be_bytes().as_slice(),m.durable_sequence.to_be_bytes().as_slice()])? == 1, "schema11 migration CAS");
        }
        compare_projection(&tx, &expected)?;
        self.confirm_namespace_identity_v1()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_before_commit");
        tx.commit()?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_after_commit");
        drop(c);
        sync_store_commit_boundary_v0(&self.path)?;
        #[cfg(test)]
        park_for_sigkill_commit_boundary_v0("incremental_schema11_after_fsync");
        self.confirm_namespace_identity_v1()?;
        let fresh = open_immutable_connection_v0(&self.path)?;
        verify_schema(&fresh)?;
        let fresh_tx = fresh.unchecked_transaction()?;
        let metadata = load_metadata_v0(&fresh_tx, &self.config)?;
        let confirmed = projection_with_budget(&fresh_tx, &self.config, &metadata, budget)?;
        compare_projection(&fresh_tx, &confirmed)?;
        ensure!(
            metadata.head == m.head
                && metadata.durable_sequence == m.durable_sequence
                && confirmed.pin == expected.pin,
            "schema11 migration fresh confirmation differs"
        );
        self.confirm_namespace_identity_v1()?;
        let mut pin = self
            .incremental_migration_pin
            .lock()
            .map_err(|_| anyhow::anyhow!("schema11 migration pin lock"))?;
        ensure!(*pin == pinned, "schema11 migration pin raced");
        *pin = Some(expected.pin);
        Ok(())
    }
}
