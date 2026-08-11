use std::collections::BTreeMap;

use rusqlite::Connection;

use crate::SafetyStoreErrorV0;

pub(crate) const JOURNAL_SCHEMA_VERSION_V2: u16 = 2;
pub(crate) const TRANSITION_CONTEXT_CODEC_V0: u16 = 0;
pub(crate) const MAXIMUM_SQL_STATE_RECORD_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAXIMUM_TRANSITION_CONTEXT_BYTES_V0: usize = 328;

pub(crate) const JOURNAL_SCHEMA_SQL_V2: &str = "
    CREATE TABLE safety_store_metadata_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        journal_schema INTEGER NOT NULL CHECK(journal_schema=2),
        journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
        core_record_codec INTEGER NOT NULL CHECK(core_record_codec=0),
        safety_schema INTEGER NOT NULL CHECK(safety_schema=8),
        core_config_ref BLOB NOT NULL CHECK(length(core_config_ref)=32),
        verifier_profile_ref BLOB NOT NULL CHECK(length(verifier_profile_ref)=32),
        maximum_record_bytes_be BLOB NOT NULL CHECK(length(maximum_record_bytes_be)=8),
        maximum_blob_bytes_be BLOB NOT NULL CHECK(length(maximum_blob_bytes_be)=8),
        maximum_database_bytes_be BLOB NOT NULL CHECK(length(maximum_database_bytes_be)=8),
        transition_codec INTEGER NOT NULL CHECK(transition_codec=0),
        metadata_checksum BLOB NOT NULL CHECK(length(metadata_checksum)=32)
    ) STRICT;
    CREATE TABLE safety_state_records_v0 (
        revision_be BLOB PRIMARY KEY NOT NULL CHECK(length(revision_be)=8),
        predecessor_revision_be BLOB
            CHECK(predecessor_revision_be IS NULL OR length(predecessor_revision_be)=8),
        predecessor_chain_checksum BLOB
            CHECK(predecessor_chain_checksum IS NULL OR length(predecessor_chain_checksum)=32),
        state_record_bytes BLOB NOT NULL
            CHECK(length(state_record_bytes)>0 AND length(state_record_bytes)<=67108864),
        state_record_checksum BLOB NOT NULL CHECK(length(state_record_checksum)=32),
        transition_context_bytes BLOB NOT NULL
            CHECK(length(transition_context_bytes)>=3 AND length(transition_context_bytes)<=328),
        transition_context_checksum BLOB NOT NULL CHECK(length(transition_context_checksum)=32),
        chain_checksum BLOB NOT NULL CHECK(length(chain_checksum)=32),
        UNIQUE(revision_be, chain_checksum),
        CHECK(
            (revision_be=x'0000000000000000' AND predecessor_revision_be IS NULL
                AND predecessor_chain_checksum IS NULL) OR
            (revision_be<>x'0000000000000000' AND predecessor_revision_be IS NOT NULL
                AND predecessor_chain_checksum IS NOT NULL)
        )
    ) STRICT;
    CREATE TABLE safety_state_head_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        active_revision_be BLOB NOT NULL CHECK(length(active_revision_be)=8),
        active_chain_checksum BLOB NOT NULL CHECK(length(active_chain_checksum)=32),
        retention_floor_revision_be BLOB NOT NULL CHECK(length(retention_floor_revision_be)=8),
        head_checksum BLOB NOT NULL CHECK(length(head_checksum)=32),
        FOREIGN KEY(active_revision_be, active_chain_checksum)
            REFERENCES safety_state_records_v0(revision_be, chain_checksum)
    ) STRICT;
    CREATE TABLE safety_state_accounting_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        record_count INTEGER NOT NULL CHECK(record_count>=1 AND record_count<=2),
        state_bytes INTEGER NOT NULL CHECK(state_bytes>0),
        transition_bytes INTEGER NOT NULL CHECK(transition_bytes>=3)
    ) STRICT;
    CREATE TABLE safety_store_halt_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        reason_code INTEGER NOT NULL CHECK(reason_code>0),
        revision_be BLOB CHECK(revision_be IS NULL OR length(revision_be)=8),
        evidence_checksum BLOB NOT NULL CHECK(length(evidence_checksum)=32),
        halt_checksum BLOB NOT NULL CHECK(length(halt_checksum)=32)
    ) STRICT;
";

pub(crate) fn validate_canonical_schema(connection: &Connection) -> Result<(), SafetyStoreErrorV0> {
    let canonical = Connection::open_in_memory()
        .map_err(|error| SafetyStoreErrorV0::sqlite("open canonical schema", error))?;
    canonical
        .execute_batch(JOURNAL_SCHEMA_SQL_V2)
        .map_err(|error| SafetyStoreErrorV0::sqlite("install canonical schema", error))?;
    if schema_objects(connection)? != schema_objects(&canonical)? {
        return Err(SafetyStoreErrorV0::SchemaMismatch);
    }
    Ok(())
}

fn schema_objects(
    connection: &Connection,
) -> Result<BTreeMap<(String, String), String>, SafetyStoreErrorV0> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|error| SafetyStoreErrorV0::sqlite("prepare schema allowlist", error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|error| SafetyStoreErrorV0::sqlite("query schema allowlist", error))?;
    let mut objects = BTreeMap::new();
    for row in rows {
        let (kind, name, sql) =
            row.map_err(|error| SafetyStoreErrorV0::sqlite("read schema allowlist", error))?;
        let sql = sql
            .ok_or(SafetyStoreErrorV0::SchemaMismatch)?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if objects.insert((kind, name), sql).is_some() {
            return Err(SafetyStoreErrorV0::SchemaMismatch);
        }
    }
    Ok(objects)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_v1_with_safety_schema_v7_is_not_implicitly_migrated() {
        let connection = Connection::open_in_memory().expect("open historical schema fixture");
        let historical = JOURNAL_SCHEMA_SQL_V2
            .replace("journal_schema=2", "journal_schema=1")
            .replace("safety_schema=8", "safety_schema=7");
        connection
            .execute_batch(&historical)
            .expect("install historical journal-v1 schema");

        assert!(matches!(
            validate_canonical_schema(&connection),
            Err(SafetyStoreErrorV0::SchemaMismatch)
        ));
    }
}
