//! Persistent logical cache admission. DB/WAL/SHM/temp/output physical space is separate.
use rusqlite::{params, Connection, TransactionBehavior};

use super::{require, CellResultV1};

pub(super) const APPLICATION_ID: i64 = 0x5443_4c32;

/// Immutable per-cache limits; no per-fetch reset or unlimited default.
/// Logical bytes include chunk payload, manifest wire and every 32-byte key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellCacheConfigV2 {
    pub max_logical_bytes: u64,
    pub max_chunk_rows: u64,
    pub max_manifest_rows: u64,
}

impl CellCacheConfigV2 {
    pub fn validate(self) -> CellResultV1<()> {
        require(
            (1..=1_099_511_627_776).contains(&self.max_logical_bytes)
                && (1..=1_048_576).contains(&self.max_chunk_rows)
                && (1..=1_048_576).contains(&self.max_manifest_rows),
            "finite cache configuration",
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellCacheUsageV2 {
    pub logical_bytes: u64,
    pub chunk_rows: u64,
    pub manifest_rows: u64,
}

fn schema() -> Vec<(&'static str, &'static str, String)> {
    let mut objects = vec![
        ("table", "cell_manifests_v1", "CREATE TABLE cell_manifests_v1 (
            id BLOB PRIMARY KEY CHECK(length(id)=32),
            wire BLOB NOT NULL CHECK(length(wire) BETWEEN 1 AND 1048576)) STRICT".to_owned()),
        ("table", "cell_chunks_v1", "CREATE TABLE cell_chunks_v1 (
            hash BLOB PRIMARY KEY CHECK(length(hash)=32),
            bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 4194304)) STRICT".to_owned()),
        ("table", "cell_cache_quota_v2", "CREATE TABLE cell_cache_quota_v2 (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            max_bytes INTEGER NOT NULL CHECK(max_bytes BETWEEN 1 AND 1099511627776),
            max_chunks INTEGER NOT NULL CHECK(max_chunks BETWEEN 1 AND 1048576),
            max_manifests INTEGER NOT NULL CHECK(max_manifests BETWEEN 1 AND 1048576),
            used_bytes INTEGER NOT NULL, chunk_rows INTEGER NOT NULL, manifest_rows INTEGER NOT NULL,
            CONSTRAINT cell_cache_capacity CHECK(
                typeof(used_bytes)='integer' AND used_bytes BETWEEN 0 AND max_bytes AND
                typeof(chunk_rows)='integer' AND chunk_rows BETWEEN 0 AND max_chunks AND
                typeof(manifest_rows)='integer' AND manifest_rows BETWEEN 0 AND max_manifests)) STRICT".to_owned()),
        ("trigger", "cache_config_immutable", "CREATE TRIGGER cache_config_immutable
            BEFORE UPDATE OF singleton,max_bytes,max_chunks,max_manifests ON cell_cache_quota_v2
            BEGIN SELECT RAISE(ABORT,'cache_config_immutable'); END".to_owned()),
        ("trigger", "cache_config_no_delete", "CREATE TRIGGER cache_config_no_delete
            BEFORE DELETE ON cell_cache_quota_v2
            BEGIN SELECT RAISE(ABORT,'cache_config_immutable'); END".to_owned()),
        ("trigger", "cache_config_no_replace", "CREATE TRIGGER cache_config_no_replace
            BEFORE INSERT ON cell_cache_quota_v2 WHEN EXISTS(SELECT 1 FROM cell_cache_quota_v2)
            BEGIN SELECT RAISE(ABORT,'cache_config_immutable'); END".to_owned()),
    ];
    for (table, data, counter) in [
        ("cell_chunks_v1", "bytes", "chunk_rows"),
        ("cell_manifests_v1", "wire", "manifest_rows"),
    ] {
        for (event, suffix, bytes, rows) in [
            ("INSERT", "insert", format!("length(NEW.{data})+32"), "+1"),
            (
                "UPDATE",
                "update",
                format!("length(NEW.{data})-length(OLD.{data})"),
                "+0",
            ),
            ("DELETE", "delete", format!("-length(OLD.{data})-32"), "-1"),
        ] {
            // AFTER INSERT does not fire on the UPDATE arm of an UPSERT. The
            // same-hash retry therefore never briefly charges a duplicate row.
            let name = match (table, suffix) {
                ("cell_chunks_v1", "insert") => "cache_chunk_insert",
                ("cell_chunks_v1", "update") => "cache_chunk_update",
                ("cell_chunks_v1", "delete") => "cache_chunk_delete",
                (_, "insert") => "cache_manifest_insert",
                (_, "update") => "cache_manifest_update",
                _ => "cache_manifest_delete",
            };
            objects.push((
                "trigger",
                name,
                format!(
                    "CREATE TRIGGER {name} AFTER {event} ON {table} BEGIN
                 UPDATE cell_cache_quota_v2 SET used_bytes=used_bytes+({bytes}),
                 {counter}={counter}{rows} WHERE singleton=1; END"
                ),
            ));
        }
    }
    objects.sort_by_key(|(_, name, _)| *name);
    objects
}

fn validate_schema(connection: &Connection) -> CellResultV1<()> {
    let expected = schema();
    let max_kind = expected
        .iter()
        .map(|(kind, _, _)| kind.len())
        .max()
        .unwrap();
    let max_name = expected
        .iter()
        .map(|(_, name, _)| name.len())
        .max()
        .unwrap();
    let max_sql = expected.iter().map(|(_, _, sql)| sql.len()).max().unwrap();
    // Bound our own row/string copies before Rust allocation. SQLite's internal
    // parsing of an externally modified schema is a separate physical limit.
    // Do not ORDER BY an untrusted catalog before applying this row bound.
    let mut query = connection.prepare(
        "SELECT CASE WHEN length(CAST(type AS BLOB))<=?1 THEN type END,
                CASE WHEN length(CAST(name AS BLOB))<=?2 THEN name END,
                CASE WHEN length(CAST(sql AS BLOB))<=?3 THEN sql END
         FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' LIMIT ?4",
    )?;
    let mut actual = query
        .query_map(
            params![max_kind, max_name, max_sql, expected.len() + 1],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    require(actual.len() == expected.len(), "cache schema objects")?;
    actual.sort_by(|left, right| left.1.cmp(&right.1));
    for ((kind, name, sql), (expected_kind, expected_name, expected_sql)) in
        actual.iter().zip(expected)
    {
        require(
            kind.as_deref() == Some(expected_kind)
                && name.as_deref() == Some(expected_name)
                && sql.as_deref() == Some(expected_sql.as_str()),
            "cache schema definition",
        )?;
    }
    Ok(())
}

pub(super) fn audit(
    connection: &Connection,
    expected: Option<CellCacheConfigV2>,
) -> CellResultV1<CellCacheUsageV2> {
    validate_schema(connection)?;
    let (config, usage) = connection.query_row(
        "SELECT max_bytes,max_chunks,max_manifests,used_bytes,chunk_rows,manifest_rows
         FROM cell_cache_quota_v2 WHERE singleton=1",
        [],
        |row| {
            Ok((
                CellCacheConfigV2 {
                    max_logical_bytes: row.get(0)?,
                    max_chunk_rows: row.get(1)?,
                    max_manifest_rows: row.get(2)?,
                },
                CellCacheUsageV2 {
                    logical_bytes: row.get(3)?,
                    chunk_rows: row.get(4)?,
                    manifest_rows: row.get(5)?,
                },
            ))
        },
    )?;
    config.validate()?;
    require(
        expected.is_none_or(|value| value == config),
        "cache configuration differs",
    )?;
    let mut logical = 0_u64;
    for (table, data, limit, rows) in [
        (
            "cell_chunks_v1",
            "bytes",
            config.max_chunk_rows,
            usage.chunk_rows,
        ),
        (
            "cell_manifests_v1",
            "wire",
            config.max_manifest_rows,
            usage.manifest_rows,
        ),
    ] {
        // Read at most cap+1 identities, without copying the stored BLOBs into
        // Rust. A malformed oversized catalog is refused, never repaired/reset.
        let (count, bytes): (u64, u64) = connection.query_row(
            &format!(
                "SELECT count(*),coalesce(sum(length({data})+32),0)
             FROM (SELECT {data} FROM {table} LIMIT ?1)"
            ),
            [limit + 1],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        require(count <= limit && count == rows, "cache row accounting")?;
        logical = logical
            .checked_add(bytes)
            .ok_or(super::CellErrorV1::Invalid("cache accounting overflow"))?;
    }
    require(
        logical == usage.logical_bytes && logical <= config.max_logical_bytes,
        "cache byte accounting",
    )?;
    Ok(usage)
}

pub(super) fn open(
    connection: &Connection,
    expected: Option<CellCacheConfigV2>,
    writable: bool,
) -> CellResultV1<()> {
    if let Some(config) = expected {
        config.validate()?;
    }
    let transaction = rusqlite::Transaction::new_unchecked(
        connection,
        if writable {
            TransactionBehavior::Immediate
        } else {
            TransactionBehavior::Deferred
        },
    )?;
    let application: i64 =
        transaction.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if writable && application == 0 && version == 0 {
        let config = expected.ok_or(super::CellErrorV1::Invalid("cache configuration required"))?;
        let populated: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' LIMIT 1)",
            [],
            |row| row.get(0),
        )?;
        require(!populated, "foreign cache database")?;
        for (kind, _, sql) in schema().iter().filter(|(kind, _, _)| *kind == "table") {
            debug_assert_eq!(*kind, "table");
            transaction.execute_batch(sql)?;
        }
        for (_, _, sql) in schema().iter().filter(|(kind, _, _)| *kind == "trigger") {
            transaction.execute_batch(sql)?;
        }
        transaction.execute(
            "INSERT INTO cell_cache_quota_v2 VALUES(1,?1,?2,?3,0,0,0)",
            params![
                config.max_logical_bytes,
                config.max_chunk_rows,
                config.max_manifest_rows
            ],
        )?;
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        transaction.pragma_update(None, "user_version", 2)?;
    } else {
        require(
            application == APPLICATION_ID && version == 2,
            "cache namespace",
        )?;
    }
    audit(&transaction, expected)?;
    transaction.commit()?;
    Ok(())
}
