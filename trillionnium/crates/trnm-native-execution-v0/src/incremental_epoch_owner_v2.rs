//! Explicit schema7→11 migration and the closed, immutable migration projection.
//! Later checkpoints require a separately implemented writer; this initial owner
//! cannot prepare, commit, attach, sign, export, or discard any retained record.
use super::*;
use rusqlite::types::{Value, ValueRef};
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

fn projection(
    tx: &rusqlite::Transaction<'_>,
    config: &NativeApplicationConfigV0,
    m: &MetadataV0,
) -> Result<Projection> {
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
    let mut budget = trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0();
    let schema = epoch_durable::schema_version(tx)?;
    ensure!(
        matches!(schema, COMMIT_SCHEMA_VERSION | SCHEMA_VERSION),
        "schema11 exact migration source"
    );
    let policy = if schema == SCHEMA_VERSION {
        OwnerAuditPolicy::MigrationProjection
    } else {
        OwnerAuditPolicy::MigrationSource
    };
    let (base, edge, audited) = audit_owner_with_policy(tx, config, m, policy, &mut budget)?;
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
        m.head.height().get() < geometry.checkpoint_height().get(),
        "schema11 migration after next checkpoint"
    );
    let first_p = load_epoch_p(tx, first.block)?.context("schema11 original first P missing")?;
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
        p.validate_context(config, &epoch_context)?;
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
            p.replay_parent
                == (ReplayHead {
                    version: 0,
                    root: base.source_replay
                })
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
        descendant::validate_p(&p, config, &set, &parameters, base.source.height().get())?;
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
        let (parent, suffix) = ordinary_replay_parent(p, &ordinary, &first_p)?;
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
        ni_p == epochs.len() + ordinary.len() && ni_edges == 1,
        "schema11 sparse/native inventory differs"
    );
    let records = bounded_blocks(tx, "native_incremental_epoch_descendant_commit_v1")?
        .into_iter()
        .map(|block| {
            descendant::load_commit(tx, block)?.context("schema11 ordinary original proof missing")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        m.head != first.head || records.is_empty(),
        "schema11 committed ordinary rows above first head"
    );
    let mut record_digests = vec![edge.checksum, first.checksum];
    record_digests.extend(records.iter().map(|r| r.checksum));
    record_digests.sort();
    let mut fields = vec![
        base.anchor.to_vec(),
        m.durable_sequence.to_be_bytes().to_vec(),
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
                number_value(m.durable_sequence),
                blob(pin),
                blob(edge.binding),
                blob(&prefix),
                number_value(0),
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
    for (block, digest, kind) in epochs
        .iter()
        .map(|p| (p.block, p.digest, 1))
        .chain(ordinary.values().map(|p| (p.block, p.digest, 0)))
    {
        rows.push(
            ProjectedRow::new(
                2,
                vec![
                    blob(block),
                    blob(digest),
                    Value::Integer(kind),
                    blob(&prefix),
                    Value::Null,
                    Value::Null,
                    Value::Null,
                ],
            )
            .finish(config, base.anchor, &[], &[4, 5, 6], &[])?,
        );
    }
    for (table, r) in std::iter::once((4, &first)).chain(records.iter().map(|r| (5, r))) {
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
    Ok(Projection {
        rows,
        pin,
        old_pin: edge.checksum,
    })
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
    /// Schema11 currently admits only this generation-zero migration projection.
    pub fn upgrade_incremental_multi_epoch_schema_v2(&self) -> Result<()> {
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
        let expected = projection(&tx, &self.config, &m)?;
        let pinned = *self
            .incremental_migration_pin
            .lock()
            .map_err(|_| anyhow::anyhow!("schema11 migration pin lock"))?;
        ensure!(
            pinned == Some(expected.old_pin)
                || (schema == SCHEMA_VERSION && pinned == Some(expected.pin)),
            "schema11 migration owner pin changed"
        );
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
        let metadata = load_metadata_v0(&fresh, &self.config)?;
        ensure!(
            metadata.head == m.head
                && metadata.durable_sequence == m.durable_sequence
                && audit_anchor(&fresh, &self.config, &metadata)? == expected.pin,
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
