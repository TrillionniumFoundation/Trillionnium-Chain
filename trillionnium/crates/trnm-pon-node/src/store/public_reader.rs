//! Explicit cfg(test) History reader research. Production keeps held-owner reads
//! after the complete-operation comparison found regressions. No runtime option.
//! Operation-local snapshots retain the Node as the sole writer.
//! A snapshot result cannot escape before the actual owner revalidates its epoch,
//! namespace, source-derived schema and every used on-disk query/body fact.
use super::{bytes32, fixed_blob, optional_fixed_blob, plain, schema, Node, Record};
use crate::{ensure, Error, Packet, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::PathBuf,
};
use trnm_protocol::pon_wire::{hash, Hash};

const MAXIMUM_PACKET: usize = 1_048_576;

/// One original cumulative allowance, including both snapshot and final owner
/// queries. Two mandatory rollback slots are reserved before any SQL begins.
struct SqlBudget {
    used: u64,
    maximum: u64,
    cleanup: u64,
}
impl SqlBudget {
    fn new(maximum: u64) -> Result<Self> {
        // Invalid trusted configuration retains the original owner policy.
        ensure(
            (3..=crate::ancestry_index::READ_SQL_BUDGET).contains(&maximum),
            "ANCESTRY_INDEX_BUDGET",
        )?;
        Ok(Self {
            used: 0,
            maximum,
            cleanup: 2,
        })
    }
    fn available(&self) -> u64 {
        self.maximum - self.used - self.cleanup
    }
    fn query(&mut self, progress: &mut dyn FnMut(u64) -> Result<()>) -> Result<()> {
        if self.available() == 0 {
            return Err(Error::public_history_budget());
        }
        self.used += 1;
        progress(self.used)
    }
    fn rollback(&mut self) {
        assert!(self.cleanup > 0);
        self.cleanup -= 1;
        self.used += 1;
    }
}

struct Pin {
    directory: PathBuf,
    directory_id: (u64, u64),
    database_id: (u64, u64),
    owner: File,
    schema: BTreeMap<String, String>,
    context: crate::ancestry_index::Context,
    schema_id: Hash,
    active: (Hash, u64),
    active_record: Record,
    slot: u64,
    external_version: u64,
    sidecars: [Option<(u64, u64)>; 2],
}
pub(crate) struct PublicHistorySnapshot {
    pin: Pin,
    tip: Hash,
    after: Hash,
    budget: SqlBudget,
}
pub(crate) struct PublicHistoryRead {
    pin: Pin,
    reads: crate::ancestry_index::ReadSet,
    body: Option<(Hash, usize, Hash)>,
    page: Value,
    budget: SqlBudget,
}

fn external_version(
    db: &Connection,
    budget: &mut SqlBudget,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<u64> {
    budget.query(progress)?;
    Ok(db.query_row("PRAGMA data_version", [], |row| row.get(0))?)
}
fn sidecar(path: &std::path::Path) -> Result<Option<(u64, u64)>> {
    match fs::symlink_metadata(path) {
        Ok(value) => Ok(Some((value.dev(), value.ino()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
fn active(
    db: &Connection,
    budget: &mut SqlBudget,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<(Hash, u64)> {
    budget.query(progress)?;
    let (tip, generation) = db.query_row(
        "SELECT tip,generation FROM active WHERE singleton=1",
        [],
        |row| Ok((fixed_blob::<32>(row, 0)?, row.get(1)?)),
    )?;
    Ok((bytes32(tip)?, generation))
}
fn record(
    db: &Connection,
    id: Hash,
    budget: &mut SqlBudget,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<Record> {
    budget.query(progress)?;
    let row = db
        .query_row(
            "SELECT parent,height,chainwork,state_root FROM blocks WHERE id=?",
            [id.as_slice()],
            |row| {
                Ok((
                    optional_fixed_blob::<32>(row, 0)?,
                    row.get(1)?,
                    fixed_blob::<64>(row, 2)?,
                    fixed_blob::<32>(row, 3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| Error::from("UNKNOWN_PARENT").local_integrity())?;
    Ok(Record {
        parent: row
            .0
            .map(bytes32)
            .transpose()
            .map_err(Error::local_integrity)?,
        height: row.1,
        work: crate::consensus::Work::from_bytes(
            super::bytes64(row.2).map_err(Error::local_integrity)?,
        ),
        root: bytes32(row.3).map_err(Error::local_integrity)?,
    })
}
fn same_record(a: &Record, b: &Record) -> bool {
    a.parent == b.parent && a.height == b.height && a.work == b.work && a.root == b.root
}
fn context_values(
    db: &Connection,
    schema_id: Hash,
    parameters: Hash,
    genesis: Hash,
    expected_schema: &BTreeMap<String, String>,
    budget: &mut SqlBudget,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<()> {
    for (key, expected) in [
        ("schema", schema_id),
        ("parameters", parameters),
        ("genesis", genesis),
    ] {
        budget.query(progress)?;
        let value: Option<Vec<u8>> = db
            .query_row("SELECT value FROM metadata WHERE key=?", [key], |row| {
                fixed_blob::<32>(row, 0)
            })
            .optional()?;
        ensure(
            value.as_deref() == Some(expected.as_slice()),
            "STORAGE_CONTEXT",
        )
        .map_err(Error::local_integrity)?;
    }
    budget.query(progress)?;
    ensure(schema(db)? == *expected_schema, "SCHEMA").map_err(Error::local_integrity)
}
fn context(
    db: &Connection,
    pin: &Pin,
    budget: &mut SqlBudget,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<()> {
    context_values(
        db,
        pin.schema_id,
        pin.context.parameters,
        pin.context.genesis,
        &pin.schema,
        budget,
        progress,
    )
}
fn ready(
    db: &Connection,
    budget: &mut SqlBudget,
    progress: &mut dyn FnMut(u64) -> Result<()>,
) -> Result<()> {
    budget.query(progress)?;
    let done: Option<bool> = db
        .query_row("SELECT done FROM reorg WHERE singleton=1", [], |row| {
            row.get(0)
        })
        .optional()?;
    ensure(done != Some(false), "REORG_IN_PROGRESS")
}
impl Pin {
    fn namespace(&self) -> Result<()> {
        ensure(
            !super::authenticated_migration_pending(&self.directory)?,
            "NATIVE_STATE_MIGRATION_PENDING",
        )?;
        let dir = fs::symlink_metadata(&self.directory)?;
        ensure(
            dir.is_dir() && (dir.dev(), dir.ino()) == self.directory_id,
            "NAMESPACE_CHANGED",
        )?;
        for name in [
            "native.sqlite",
            "native.sqlite-wal",
            "native.sqlite-shm",
            "owner.lock",
        ] {
            plain(&self.directory.join(name))?;
        }
        for (index, name) in ["native.sqlite-wal", "native.sqlite-shm"]
            .iter()
            .enumerate()
        {
            ensure(
                sidecar(&self.directory.join(name))? == self.sidecars[index],
                "NAMESPACE_CHANGED",
            )?;
        }
        let db = fs::metadata(self.directory.join("native.sqlite"))?;
        ensure(
            (db.dev(), db.ino()) == self.database_id,
            "DATABASE_REPLACED",
        )?;
        let owner = fs::metadata(self.directory.join("owner.lock"))?;
        let held = self.owner.metadata()?;
        ensure(
            (owner.dev(), owner.ino()) == (held.dev(), held.ino()),
            "OWNER_REPLACED",
        )
    }
    fn epoch(
        &self,
        db: &Connection,
        budget: &mut SqlBudget,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<()> {
        let current = active(db, budget, progress)?;
        ensure(current.1 == self.active.1, "STALE_VIEW")?;
        ensure(current.0 == self.active.0, "STALE_VIEW").map_err(Error::local_integrity)?;
        budget.query(progress)?;
        let slot: u64 = db.query_row(
            "SELECT state_slot FROM active WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        ensure(
            slot == self.slot
                && same_record(
                    &record(db, self.active.0, budget, progress)?,
                    &self.active_record,
                ),
            "STALE_VIEW",
        )
        .map_err(Error::local_integrity)
    }
}
impl Node {
    /// Only an actual owner can choose the path/identity/epoch. Opening the fresh
    /// readonly connection occurs outside the writer mutex, under this private pin.
    pub(crate) fn prepare_public_history_snapshot(
        &self,
        tip: Hash,
        after: Hash,
        maximum_sql: u64,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<PublicHistorySnapshot> {
        progress(0)?;
        #[cfg(test)]
        let maximum_sql = self
            .public_history_test_sql_limit
            .map_or(maximum_sql, |limit| maximum_sql.min(limit));
        let mut budget = SqlBudget::new(maximum_sql)?;
        self.namespace()?;
        ready(&self.db, &mut budget, progress)?;
        context_values(
            &self.db,
            self.state_backend.schema_id(),
            self.settings.parameters(),
            self.settings.genesis(),
            &self.expected_schema,
            &mut budget,
            progress,
        )?;
        let selected = active(&self.db, &mut budget, progress)?;
        let active_record = record(&self.db, selected.0, &mut budget, progress)?;
        budget.query(progress)?;
        let slot = self.slot()?;
        let external_version = external_version(&self.db, &mut budget, progress)?;
        let pin = Pin {
            directory: self.directory.clone(),
            directory_id: self.directory_id,
            database_id: self.database_id,
            owner: self.owner.try_clone()?,
            schema: self.expected_schema.clone(),
            context: self.ancestry_context(),
            schema_id: self.state_backend.schema_id(),
            active: selected,
            active_record,
            slot,
            external_version,
            sidecars: [
                sidecar(&self.directory.join("native.sqlite-wal"))?,
                sidecar(&self.directory.join("native.sqlite-shm"))?,
            ],
        };
        progress(budget.used)?;
        Ok(PublicHistorySnapshot {
            pin,
            tip,
            after,
            budget,
        })
    }
    pub(crate) fn finish_public_history_snapshot(
        &self,
        mut read: PublicHistoryRead,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<Value> {
        progress(read.budget.used)?;
        self.namespace()?;
        ready(&self.db, &mut read.budget, progress)?;
        read.pin.namespace()?;
        ensure(
            self.directory_id == read.pin.directory_id
                && self.database_id == read.pin.database_id
                && self.state_backend.schema_id() == read.pin.schema_id
                && self.settings.network() == read.pin.context.network,
            "STORAGE_CONTEXT",
        )
        .map_err(Error::local_integrity)?;
        // data_version is compared on the SAME durable owner's connection.
        // A foreign write-and-restore cannot be hidden by an unchanged generation.
        ensure(
            external_version(&self.db, &mut read.budget, progress)? == read.pin.external_version,
            "STORAGE_PACKET",
        )
        .map_err(Error::local_integrity)?;
        read.budget.query(progress)?;
        let tx = self.db.unchecked_transaction()?;
        let changes = tx.total_changes();
        context(&tx, &read.pin, &mut read.budget, progress)?;
        ready(&tx, &mut read.budget, progress)?;
        read.pin.epoch(&tx, &mut read.budget, progress)?;
        let facts = read.reads.len() as u64;
        read.reads.revalidate(&tx, &mut |index| {
            if index < facts {
                read.budget.query(progress)
            } else {
                progress(read.budget.used)
            }
        })?;
        if let Some((id, length, digest)) = read.body {
            read.budget.query(progress)?;
            let actual_length: Option<usize> = tx.query_row(
                "SELECT length(packet) FROM blocks WHERE id=?",
                [id.as_slice()],
                |row| row.get(0),
            )?;
            ensure(actual_length == Some(length), "STORAGE_PACKET")
                .map_err(Error::local_integrity)?;
            read.budget.query(progress)?;
            let actual: Vec<u8> = tx
                .query_row(
                    "SELECT packet FROM blocks WHERE id=? AND length(packet)<=?",
                    params![id.as_slice(), MAXIMUM_PACKET],
                    |row| row.get(0),
                )
                .map_err(|error| Error::from(error).local_integrity())?;
            ensure(
                hash(b"native-history-read-body-v1", &[&actual]) == digest,
                "STORAGE_PACKET",
            )
            .map_err(Error::local_integrity)?;
        }
        progress(read.budget.used)?;
        ensure(tx.total_changes() == changes, "STORAGE_WRITE").map_err(Error::local_integrity)?;
        read.budget.rollback();
        tx.rollback()?;
        read.pin.namespace()?;
        read.pin.epoch(&self.db, &mut read.budget, progress)?;
        ensure(
            external_version(&self.db, &mut read.budget, progress)? == read.pin.external_version,
            "STORAGE_PACKET",
        )
        .map_err(Error::local_integrity)?;
        progress(read.budget.used)?;
        Ok(read.page)
    }
}
impl PublicHistorySnapshot {
    pub(crate) fn read(
        mut self,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<PublicHistoryRead> {
        progress(self.budget.used)?;
        self.pin.namespace()?;
        let db = Connection::open_with_flags(
            self.pin.directory.join("native.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        self.budget.query(progress)?;
        db.pragma_update(None, "query_only", true)?;
        self.budget.query(progress)?;
        let tx = db.unchecked_transaction()?;
        context(&tx, &self.pin, &mut self.budget, progress)?;
        ready(&tx, &mut self.budget, progress)?;
        self.pin.epoch(&tx, &mut self.budget, progress)?;
        let mut reads = crate::ancestry_index::ReadSet::default();
        let allowance = self.budget.available();
        if allowance < 3 {
            return Err(Error::public_history_budget());
        }
        let lookup = crate::ancestry_index::next_recording(
            &tx,
            self.pin.context,
            self.tip,
            self.after,
            allowance,
            &mut |_| self.budget.query(progress),
            &mut reads,
        )?;
        let mut packets = Vec::new();
        let mut body = None;
        let mut next = self.after;
        if let Some(id) = lookup.next {
            self.budget.query(progress)?;
            let length: Option<usize> = tx.query_row(
                "SELECT length(packet) FROM blocks WHERE id=?",
                [id.as_slice()],
                |row| row.get(0),
            )?;
            ensure(
                length.is_some_and(|n| n > 0 && n <= MAXIMUM_PACKET),
                "PUBLIC_HISTORY_BYTES",
            )
            .map_err(Error::local_integrity)?;
            self.budget.query(progress)?;
            let raw: Vec<u8> = tx.query_row(
                "SELECT packet FROM blocks WHERE id=? AND length(packet)<=?",
                params![id.as_slice(), MAXIMUM_PACKET],
                |row| row.get(0),
            )?;
            let packet = Packet::decode(&raw).map_err(Error::local_integrity)?;
            ensure(
                packet.id()? == id
                    && packet.header.parent == self.after
                    && packet.header.height == lookup.height,
                "STORAGE_PACKET",
            )?;
            progress(self.budget.used)?;
            let encoded = packet.encode()?;
            ensure(
                encoded == raw
                    && encoded
                        .len()
                        .checked_mul(2)
                        .is_some_and(|n| n <= 2 * MAXIMUM_PACKET),
                "PUBLIC_HISTORY_BYTES",
            )?;
            body = Some((id, raw.len(), hash(b"native-history-read-body-v1", &[&raw])));
            packets.push(hex::encode(encoded));
            next = id;
        }
        progress(self.budget.used)?;
        let page = serde_json::to_value(crate::ingress::Page {
            schema: "pon-native-history-v1".into(),
            network: hex::encode(self.pin.context.network),
            parameters: hex::encode(self.pin.context.parameters),
            genesis: hex::encode(self.pin.context.genesis),
            tip: hex::encode(self.tip),
            after: hex::encode(self.after),
            complete: next == self.tip,
            next: hex::encode(next),
            packets,
        })?;
        self.budget.rollback();
        tx.rollback()?;
        self.pin.namespace()?;
        progress(self.budget.used)?;
        Ok(PublicHistoryRead {
            pin: self.pin,
            reads,
            body,
            page,
            budget: self.budget,
        })
    }
}

impl PublicHistoryRead {
    /// Local diagnostic only: the page remains private until the actual owner
    /// completes revalidation. This is not a signed client proof or permission.
    #[cfg(test)]
    pub(crate) fn snapshot_observation(&self) -> Value {
        serde_json::json!({"snapshot_active_tip":hex::encode(self.pin.active.0),"snapshot_generation":self.pin.active.1,"snapshot_external_data_version":self.pin.external_version,"unique_query_facts":self.reads.len(),"query_fact_limit":crate::ancestry_index::READ_SQL_BUDGET,"cumulative_sql_used":self.budget.used,"cumulative_sql_limit":self.budget.maximum,"reserved_cleanup_statements":self.budget.cleanup,"body_bytes":self.body.map(|body|body.1).unwrap_or(0),"scope":"one actual readonly snapshot, awaiting final owner revalidation","execution_authority":false,"public_network_ready":false,"production_activation":false})
    }
}

#[cfg(test)]
#[path = "public_reader_tests.rs"]
mod tests;
