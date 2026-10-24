//! Persistent logical admission plus a main DB-image length/page cap.
//! This is not allocated-block reservation or a WAL/SHM/temp/output disk limit.
use rusqlite::{params, Connection, TransactionBehavior};

use super::{require, CellResultV1};

pub(super) const APPLICATION_ID: i64 = 0x5443_4c33;

/// Immutable per-cache limits; no per-fetch reset or unlimited default.
/// Logical bytes include chunk payload, manifest wire and every 32-byte key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellCacheConfigV3 {
    /// Main database image/file length only; not total disk usage or reservation.
    pub max_database_bytes: u64,
    pub max_logical_bytes: u64,
    pub max_chunk_rows: u64,
    pub max_manifest_rows: u64,
}

impl CellCacheConfigV3 {
    pub fn validate(self) -> CellResultV1<()> {
        require(
            (262_144..=2_199_023_255_552).contains(&self.max_database_bytes)
                && self.max_database_bytes.is_multiple_of(4096)
                && (1..=1_099_511_627_776).contains(&self.max_logical_bytes)
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
        ("table", "cell_cache_quota_v3", "CREATE TABLE cell_cache_quota_v3 (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            max_bytes INTEGER NOT NULL CHECK(max_bytes BETWEEN 1 AND 1099511627776),
            max_chunks INTEGER NOT NULL CHECK(max_chunks BETWEEN 1 AND 1048576),
            max_manifests INTEGER NOT NULL CHECK(max_manifests BETWEEN 1 AND 1048576),
            max_database_bytes INTEGER NOT NULL CHECK(max_database_bytes BETWEEN 262144 AND 2199023255552 AND max_database_bytes%4096=0),
            used_bytes INTEGER NOT NULL, chunk_rows INTEGER NOT NULL, manifest_rows INTEGER NOT NULL,
            CONSTRAINT cell_cache_capacity CHECK(
                typeof(used_bytes)='integer' AND used_bytes BETWEEN 0 AND max_bytes AND
                typeof(chunk_rows)='integer' AND chunk_rows BETWEEN 0 AND max_chunks AND
                typeof(manifest_rows)='integer' AND manifest_rows BETWEEN 0 AND max_manifests)) STRICT".to_owned()),
        ("trigger", "cache_config_immutable", "CREATE TRIGGER cache_config_immutable
            BEFORE UPDATE OF singleton,max_bytes,max_chunks,max_manifests,max_database_bytes ON cell_cache_quota_v3
            BEGIN SELECT RAISE(ABORT,'cache_config_immutable'); END".to_owned()),
        ("trigger", "cache_config_no_delete", "CREATE TRIGGER cache_config_no_delete
            BEFORE DELETE ON cell_cache_quota_v3
            BEGIN SELECT RAISE(ABORT,'cache_config_immutable'); END".to_owned()),
        ("trigger", "cache_config_no_replace", "CREATE TRIGGER cache_config_no_replace
            BEFORE INSERT ON cell_cache_quota_v3 WHEN EXISTS(SELECT 1 FROM cell_cache_quota_v3)
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
                 UPDATE cell_cache_quota_v3 SET used_bytes=used_bytes+({bytes}),
                 {counter}={counter}{rows} WHERE singleton=1; END"
                ),
            ));
        }
    }
    objects.sort_by_key(|(_, name, _)| *name);
    objects
}

fn catalog_schema() -> Vec<(&'static str, &'static str, &'static str, Option<String>)> {
    let mut objects: Vec<_> = schema()
        .into_iter()
        .map(|(kind, name, sql)| {
            let table = match name {
                "cell_cache_quota_v3"
                | "cache_config_immutable"
                | "cache_config_no_delete"
                | "cache_config_no_replace" => "cell_cache_quota_v3",
                "cell_chunks_v1" | "cache_chunk_insert" | "cache_chunk_update"
                | "cache_chunk_delete" => "cell_chunks_v1",
                "cell_manifests_v1"
                | "cache_manifest_insert"
                | "cache_manifest_update"
                | "cache_manifest_delete" => "cell_manifests_v1",
                _ => unreachable!("fixed cache schema object"),
            };
            (kind, name, table, Some(sql))
        })
        .collect();
    // Only these two PRIMARY KEY indexes are implicit in our exact DDL.
    // INTEGER PRIMARY KEY on the quota singleton creates no automatic index.
    objects.extend([
        (
            "index",
            "sqlite_autoindex_cell_chunks_v1_1",
            "cell_chunks_v1",
            None,
        ),
        (
            "index",
            "sqlite_autoindex_cell_manifests_v1_1",
            "cell_manifests_v1",
            None,
        ),
    ]);
    objects.sort_by_key(|(_, name, _, _)| *name);
    objects
}

fn validate_schema(connection: &Connection) -> CellResultV1<()> {
    let expected = catalog_schema();
    let max_kind = expected
        .iter()
        .map(|(kind, _, _, _)| kind.len())
        .max()
        .unwrap();
    let max_name = expected
        .iter()
        .map(|(_, name, _, _)| name.len())
        .max()
        .unwrap();
    let max_table = expected
        .iter()
        .map(|(_, _, table, _)| table.len())
        .max()
        .unwrap();
    let max_sql = expected
        .iter()
        .filter_map(|(_, _, _, sql)| sql.as_ref().map(String::len))
        .max()
        .unwrap();
    // Bound our own row/string copies before Rust allocation. SQLite's internal
    // parsing of an externally modified schema is a separate physical limit.
    // No prefix can hide an object, and no ORDER BY precedes this row bound.
    let mut query = connection.prepare(
        "SELECT CASE WHEN length(CAST(type AS BLOB))<=?1 THEN type END,
                CASE WHEN length(CAST(name AS BLOB))<=?2 THEN name END,
                CASE WHEN length(CAST(tbl_name AS BLOB))<=?3 THEN tbl_name END,
                CASE WHEN length(CAST(sql AS BLOB))<=?4 THEN sql END,
                sql IS NULL
         FROM sqlite_schema LIMIT ?5",
    )?;
    let mut actual = query
        .query_map(
            params![max_kind, max_name, max_table, max_sql, expected.len() + 1],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, bool>(4)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    require(actual.len() == expected.len(), "cache schema objects")?;
    actual.sort_by(|left, right| left.1.cmp(&right.1));
    for (
        (kind, name, table, sql, raw_sql_is_null),
        (expected_kind, expected_name, expected_table, expected_sql),
    ) in actual.iter().zip(expected)
    {
        require(
            kind.as_deref() == Some(expected_kind)
            && name.as_deref() == Some(expected_name)
            && table.as_deref() == Some(expected_table)
            // An oversized non-NULL SQL value must never look like an implicit
            // index's legitimate NULL after the bounded-copy CASE expression.
            && (sql.is_none() == *raw_sql_is_null)
            && sql.as_deref() == expected_sql.as_deref(),
            "cache schema definition",
        )?;
    }
    Ok(())
}

pub(super) fn audit(
    connection: &Connection,
    expected: Option<CellCacheConfigV3>,
) -> CellResultV1<CellCacheUsageV2> {
    validate_schema(connection)?;
    let (config, usage) = connection.query_row(
        "SELECT max_bytes,max_chunks,max_manifests,used_bytes,chunk_rows,manifest_rows,max_database_bytes
         FROM cell_cache_quota_v3 WHERE singleton=1",
        [],
        |row| {
            Ok((
                CellCacheConfigV3 {
                    max_database_bytes: row.get(6)?,
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
    check_image(connection, config.max_database_bytes, false)?;
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
    expected: Option<CellCacheConfigV3>,
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
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema LIMIT 1)",
            [],
            |row| row.get(0),
        )?;
        require(!populated, "foreign cache database")?;
        transaction.pragma_update(None, "page_size", 4096)?;
        check_image(&transaction, config.max_database_bytes, true)?;
        for (kind, _, sql) in schema().iter().filter(|(kind, _, _)| *kind == "table") {
            debug_assert_eq!(*kind, "table");
            transaction.execute_batch(sql)?;
        }
        for (_, _, sql) in schema().iter().filter(|(kind, _, _)| *kind == "trigger") {
            transaction.execute_batch(sql)?;
        }
        transaction.execute(
            "INSERT INTO cell_cache_quota_v3 VALUES(1,?1,?2,?3,?4,0,0,0)",
            params![
                config.max_logical_bytes,
                config.max_chunk_rows,
                config.max_manifest_rows,
                config.max_database_bytes
            ],
        )?;
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        transaction.pragma_update(None, "user_version", 3)?;
    } else {
        require(
            application == APPLICATION_ID && version == 3,
            "cache namespace",
        )?;
    }
    audit(&transaction, expected)?;
    if writable {
        let cap: u64 = transaction.query_row(
            "SELECT max_database_bytes FROM cell_cache_quota_v3 WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        check_image(&transaction, cap, true)?;
    }
    transaction.commit()?;
    Ok(())
}

// The SQLite pager limit is connection-local, not a persistent database header.
// Every writer must reapply it; readers only audit the persisted image contract.
fn check_image(
    connection: &Connection,
    max_database_bytes: u64,
    writable: bool,
) -> CellResultV1<()> {
    let page_size: u64 = connection.pragma_query_value(None, "page_size", |r| r.get(0))?;
    let pages: u64 = connection.pragma_query_value(None, "page_count", |r| r.get(0))?;
    require(page_size == 4096, "cache database page size")?;
    let image_bytes = pages
        .checked_mul(page_size)
        .ok_or(super::CellErrorV1::Invalid("cache database image overflow"))?;
    let path = connection
        .path()
        .ok_or(super::CellErrorV1::Invalid("cache database path"))?;
    let metadata = std::fs::symlink_metadata(path)?;
    require(
        metadata.is_file()
            && metadata.len() <= max_database_bytes
            && image_bytes <= max_database_bytes,
        "cache database image cap",
    )?;
    if writable {
        let expected = max_database_bytes / page_size;
        let actual: u64 =
            connection.pragma_update_and_check(None, "max_page_count", expected, |r| r.get(0))?;
        require(actual == expected, "cache database page limit")?;
    }
    Ok(())
}
