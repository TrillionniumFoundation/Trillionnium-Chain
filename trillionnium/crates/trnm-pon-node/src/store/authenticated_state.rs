//! One fresh, explicit research namespace. No native store schema is extended.
use crate::account_archive_prototype::Context;
use crate::authenticated_state_archive::{
    check, decode, encode, ActiveCheckpoint, Error, Limits, Observation, Prepared, Progress,
    Record, Result, Selection, SCHEMA,
};
use crate::sequence_root;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;
use trnm_protocol::pon_wire::{hash, Hash};

const MAX_ROW_BYTES: usize = 32 * 1024 * 1024;
pub(crate) struct Database {
    db: Connection,
    context: Context,
    limits: Limits,
}
pub(crate) struct Loaded {
    pub record: Record,
    pub deltas: Vec<Vec<u8>>,
    pub snapshot: Option<Vec<u8>>,
}
fn context_bytes(context: Context) -> Vec<u8> {
    [context.network, context.parameters, context.genesis].concat()
}
impl Database {
    pub fn open(path: &Path, context: Context, limits: Limits) -> Result<Self> {
        limits.check()?;
        let mut db = Connection::open(path)?;
        let names: Vec<String> = db
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        let expected = [
            "authenticated_active",
            "authenticated_checkpoints",
            "authenticated_deltas",
            "authenticated_meta",
            "authenticated_snapshots",
        ];
        if !names.is_empty() && names.iter().map(String::as_str).collect::<Vec<_>>() != expected {
            return Err(Error::Context);
        }
        if names.is_empty() {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "CREATE TABLE authenticated_meta(key TEXT PRIMARY KEY,value BLOB NOT NULL);
                 CREATE TABLE authenticated_checkpoints(id BLOB PRIMARY KEY,branch BLOB UNIQUE NOT NULL,parent BLOB,height INTEGER NOT NULL,data BLOB NOT NULL);
                 CREATE TABLE authenticated_deltas(checkpoint BLOB NOT NULL,ordinal INTEGER NOT NULL,data BLOB NOT NULL,PRIMARY KEY(checkpoint,ordinal));
                 CREATE TABLE authenticated_snapshots(checkpoint BLOB PRIMARY KEY,data BLOB NOT NULL);
                 CREATE TABLE authenticated_active(singleton INTEGER PRIMARY KEY CHECK(singleton=1),checkpoint BLOB NOT NULL,generation INTEGER NOT NULL);",
            )?;
            tx.execute(
                "INSERT INTO authenticated_meta(key,value) VALUES('schema',?),('context',?)",
                params![SCHEMA.as_bytes(), context_bytes(context)],
            )?;
            tx.commit()?;
        }
        namespace(&db, context)?;
        check_budget(&db, limits)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
        Ok(Self {
            db,
            context,
            limits,
        })
    }
    pub fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let tx = self.db.unchecked_transaction()?;
        namespace(&tx, self.context)?;
        check_budget(&tx, self.limits)?;
        let result = f(&tx)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn publish(
        &mut self,
        prepared: Prepared,
        parent: Option<&Record>,
        selection: Selection,
        progress: &(impl Fn(Progress) -> bool + Sync),
    ) -> Result<()> {
        prepared.record.validate(self.context)?;
        let data = encode(&prepared.record)?;
        check(progress, Progress::BeforeTransaction)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        namespace(&tx, self.context)?;
        check(progress, Progress::AfterBegin)?;
        if let Selection::Activate { expected } = selection {
            if active(&tx)? != expected {
                return Err(Error::StaleActive);
            }
        }
        if let Some(parent) = parent {
            if load_record(&tx, self.context, parent.id)? != *parent
                || prepared.record.parent != Some(parent.id)
                || parent.height.checked_add(1) != Some(prepared.record.height)
            {
                return Err(Error::Source);
            }
        } else if prepared.record.parent.is_some() {
            return Err(Error::Source);
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM authenticated_checkpoints WHERE id=? OR branch=?)",
            params![
                prepared.record.id.as_slice(),
                prepared.record.branch.as_slice()
            ],
            |row| row.get(0),
        )?;
        if exists {
            return Err(Error::Conflict);
        }
        let id = prepared.record.id;
        for (index, bytes) in prepared.deltas.iter().enumerate() {
            if bytes.len() > MAX_ROW_BYTES {
                return Err(Error::Budget);
            }
            tx.execute(
                "INSERT INTO authenticated_deltas(checkpoint,ordinal,data) VALUES(?,?,?)",
                params![id.as_slice(), index as i64, bytes],
            )?;
            check(progress, Progress::DeltaWritten { index })?;
        }
        if let Some(bytes) = &prepared.snapshot {
            if bytes.len() > MAX_ROW_BYTES {
                return Err(Error::Budget);
            }
            tx.execute(
                "INSERT INTO authenticated_snapshots(checkpoint,data) VALUES(?,?)",
                params![id.as_slice(), bytes],
            )?;
        }
        let parent = prepared.record.parent.map(|value| value.to_vec());
        let height = i64::try_from(prepared.record.height).map_err(|_| Error::Budget)?;
        tx.execute(
            "INSERT INTO authenticated_checkpoints(id,branch,parent,height,data) VALUES(?,?,?,?,?)",
            params![
                id.as_slice(),
                prepared.record.branch.as_slice(),
                parent,
                height,
                data
            ],
        )?;
        // Check the actual newly inserted payload, including exact row count and
        // digest, before it may be selected or committed.
        load(&tx, self.context, id)?;
        check(progress, Progress::CheckpointWritten)?;
        if let Selection::Activate { expected } = selection {
            select(&tx, expected, id)?;
            check(progress, Progress::SelectionWritten)?;
        }
        // Check after the last write, including all trigger effects. Earlier
        // checks alone cannot detect a selection write that destroys an anchor.
        namespace(&tx, self.context)?;
        required_payloads(&tx, self.context, self.limits, id)?;
        check_budget(&tx, self.limits)?;
        check(progress, Progress::BeforeCommit)?;
        tx.commit()?;
        Ok(())
    }
    pub fn activate(
        &mut self,
        expected: Option<ActiveCheckpoint>,
        record: &Record,
        progress: &(impl Fn(Progress) -> bool + Sync),
    ) -> Result<ActiveCheckpoint> {
        check(progress, Progress::BeforeTransaction)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        namespace(&tx, self.context)?;
        check(progress, Progress::AfterBegin)?;
        if load_record(&tx, self.context, record.id)? != *record {
            return Err(Error::Source);
        }
        let active = select(&tx, expected, record.id)?;
        check(progress, Progress::SelectionWritten)?;
        namespace(&tx, self.context)?;
        required_payloads(&tx, self.context, self.limits, record.id)?;
        check_budget(&tx, self.limits)?;
        check(progress, Progress::BeforeCommit)?;
        tx.commit()?;
        Ok(active)
    }
}

/// Recheck the already verified record's sealed ancestor payloads after the last
/// write in the transaction. Neither concurrent corruption after the earlier
/// full read nor a write trigger can publish or select an unreadable target.
fn required_payloads(db: &Connection, context: Context, limits: Limits, id: Hash) -> Result<()> {
    let mut current = id;
    let mut child: Option<Record> = None;
    for _ in 0..limits.max_history {
        let loaded = load(db, context, current)?;
        if child.as_ref().is_some_and(|child| {
            child.parent != Some(loaded.record.id)
                || loaded.record.height.checked_add(1) != Some(child.height)
        }) {
            return Err(Error::CorruptRecord);
        }
        match loaded.record.parent {
            Some(parent) => {
                current = parent;
                child = Some(loaded.record);
            }
            None => return Ok(()),
        }
    }
    Err(Error::Budget)
}

fn namespace(db: &Connection, context: Context) -> Result<()> {
    let rows: Vec<(String, Vec<u8>)> = db
        .prepare("SELECT key,substr(value,1,257) FROM authenticated_meta ORDER BY key")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<std::result::Result<_, _>>()?;
    if rows
        != vec![
            ("context".into(), context_bytes(context)),
            ("schema".into(), SCHEMA.as_bytes().to_vec()),
        ]
    {
        return Err(Error::Context);
    }
    Ok(())
}
pub(crate) fn ids(db: &Connection) -> Result<Vec<Hash>> {
    let raw: Vec<Vec<u8>> = db
        .prepare("SELECT substr(id,1,33) FROM authenticated_checkpoints ORDER BY height,id")?
        .query_map([], |row| row.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    raw.into_iter()
        .map(|bytes| bytes.try_into().map_err(|_| Error::CorruptRecord))
        .collect()
}
pub(crate) fn load_record(db: &Connection, context: Context, id: Hash) -> Result<Record> {
    let row = db.query_row(
        "SELECT substr(branch,1,33),substr(parent,1,33),height,substr(data,1,?) FROM authenticated_checkpoints WHERE id=?",
        params![MAX_ROW_BYTES + 1, id.as_slice()],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?, row.get::<_, i64>(2)?, row.get::<_, Vec<u8>>(3)?)),
    ).optional()?.ok_or(Error::MissingCheckpoint)?;
    let record: Record = decode(&row.3)?;
    record.validate(context)?;
    if record.id != id
        || row.0 != record.branch
        || row.1 != record.parent.map(|value| value.to_vec())
        || u64::try_from(row.2).ok() != Some(record.height)
    {
        return Err(Error::CorruptRecord);
    }
    Ok(record)
}
pub(crate) fn load(db: &Connection, context: Context, id: Hash) -> Result<Loaded> {
    let record = load_record(db, context, id)?;
    let mut deltas = Vec::new();
    let mut statement = db.prepare(
        "SELECT ordinal,substr(data,1,?) FROM authenticated_deltas WHERE checkpoint=? ORDER BY ordinal",
    )?;
    let mut rows = statement.query(params![MAX_ROW_BYTES + 1, id.as_slice()])?;
    while let Some(row) = rows.next()? {
        let ordinal: i64 = row.get(0)?;
        let bytes: Vec<u8> = row.get(1)?;
        if u64::try_from(ordinal).ok() != Some(deltas.len() as u64)
            || deltas.len() as u64 >= record.delta_count
            || bytes.len() > MAX_ROW_BYTES
        {
            return Err(Error::CorruptRecord);
        }
        let _: crate::authenticated_state_archive::Delta = decode(&bytes)?;
        deltas.push(bytes);
    }
    if deltas.len() as u64 != record.delta_count
        || sequence_root("authenticated-state-deltas-v1", &deltas) != record.delta_root
    {
        return Err(Error::CorruptRecord);
    }
    let snapshot: Option<Vec<u8>> = db
        .query_row(
            "SELECT substr(data,1,?) FROM authenticated_snapshots WHERE checkpoint=?",
            params![MAX_ROW_BYTES + 1, id.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if snapshot
        .as_ref()
        .is_some_and(|bytes| bytes.len() > MAX_ROW_BYTES)
        || snapshot
            .as_ref()
            .map(|bytes| hash(b"authenticated-state-snapshot-v1", &[bytes]))
            != record.snapshot_digest
    {
        return Err(Error::CorruptRecord);
    }
    Ok(Loaded {
        record,
        deltas,
        snapshot,
    })
}
pub(crate) fn active(db: &Connection) -> Result<Option<ActiveCheckpoint>> {
    let count: u64 = db.query_row("SELECT count(*) FROM authenticated_active", [], |row| {
        row.get(0)
    })?;
    if count > 1 {
        return Err(Error::CorruptRecord);
    }
    let row = db
        .query_row(
            "SELECT singleton,substr(checkpoint,1,33),generation FROM authenticated_active",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(singleton, checkpoint, generation)| {
        if singleton != 1 || generation <= 0 {
            return Err(Error::CorruptRecord);
        }
        Ok(ActiveCheckpoint {
            checkpoint: checkpoint.try_into().map_err(|_| Error::CorruptRecord)?,
            generation: generation as u64,
        })
    })
    .transpose()
}
fn select(
    db: &Connection,
    expected: Option<ActiveCheckpoint>,
    checkpoint: Hash,
) -> Result<ActiveCheckpoint> {
    if active(db)? != expected {
        return Err(Error::StaleActive);
    }
    let generation = expected
        .map_or(Some(1), |value| value.generation.checked_add(1))
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(Error::Budget)?;
    let changed = db.execute(
        "INSERT INTO authenticated_active(singleton,checkpoint,generation) VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET checkpoint=excluded.checkpoint,generation=excluded.generation",
        params![checkpoint.as_slice(), generation],
    )?;
    let selected = ActiveCheckpoint {
        checkpoint,
        generation: generation as u64,
    };
    if changed != 1 || active(db)? != Some(selected) {
        return Err(Error::CorruptRecord);
    }
    Ok(selected)
}
pub(crate) fn observation(db: &Connection) -> Result<Observation> {
    db.query_row(
        "SELECT (SELECT count(*) FROM authenticated_checkpoints),
                (SELECT count(*) FROM authenticated_deltas),
                (SELECT count(*) FROM authenticated_snapshots),
                (SELECT coalesce(sum(length(data)),0) FROM authenticated_checkpoints)
                  +(SELECT coalesce(sum(length(data)),0) FROM authenticated_deltas)
                  +(SELECT coalesce(sum(length(data)),0) FROM authenticated_snapshots)",
        [],
        |row| {
            Ok(Observation {
                checkpoint_rows: row.get(0)?,
                delta_rows: row.get(1)?,
                snapshot_rows: row.get(2)?,
                payload_bytes: row.get(3)?,
            })
        },
    )
    .map_err(Into::into)
}
fn check_budget(db: &Connection, limits: Limits) -> Result<()> {
    let observed = observation(db)?;
    if observed.checkpoint_rows > limits.max_checkpoints
        || observed.delta_rows > limits.max_delta_rows
        || observed.payload_bytes > limits.max_payload_bytes
        || observed.snapshot_rows > 1
    {
        return Err(Error::Budget);
    }
    let orphan: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM authenticated_deltas d LEFT JOIN authenticated_checkpoints c ON c.id=d.checkpoint WHERE c.id IS NULL)
            OR EXISTS(SELECT 1 FROM authenticated_snapshots s LEFT JOIN authenticated_checkpoints c ON c.id=s.checkpoint WHERE c.id IS NULL)
            OR EXISTS(SELECT 1 FROM authenticated_active a LEFT JOIN authenticated_checkpoints c ON c.id=a.checkpoint WHERE c.id IS NULL)
            OR EXISTS(SELECT 1 FROM authenticated_checkpoints c LEFT JOIN authenticated_checkpoints p ON p.id=c.parent WHERE c.parent IS NOT NULL AND p.id IS NULL)",
        [],
        |row| row.get(0),
    )?;
    if orphan {
        return Err(Error::CorruptRecord);
    }
    active(db)?;
    Ok(())
}
