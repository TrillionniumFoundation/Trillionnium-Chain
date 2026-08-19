use std::collections::BTreeMap;

use rusqlite::Connection;

use crate::SafetyStoreErrorV0;

pub(crate) const JOURNAL_SCHEMA_VERSION_V6: u16 = 6;
pub(crate) const JOURNAL_SAFETY_SCHEMA_VERSION_V6: u16 = 12;
pub(crate) const TRANSITION_CONTEXT_CODEC_V0: u16 = 0;
pub(crate) const MAXIMUM_SQL_STATE_RECORD_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAXIMUM_TRANSITION_CONTEXT_BYTES_V0: usize = 328;

pub(crate) const JOURNAL_SCHEMA_SQL_V6: &str = "
    CREATE TABLE safety_store_metadata_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        journal_schema INTEGER NOT NULL CHECK(journal_schema=6),
        journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
        core_record_codec INTEGER NOT NULL CHECK(core_record_codec=0),
        safety_schema INTEGER NOT NULL CHECK(safety_schema=12),
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
        .execute_batch(JOURNAL_SCHEMA_SQL_V6)
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
    use sha2::{Digest, Sha256};

    const JOURNAL_SCHEMA_OBJECTS_DIGEST_DOMAIN_V0: &[u8] =
        b"trnm.consensus-safety-store.sqlite-schema-objects.v0";

    fn canonical_schema_objects_digest_v0(connection: &Connection) -> [u8; 32] {
        let objects = schema_objects(connection).expect("read canonical schema objects");
        let mut hasher = Sha256::new();
        hasher.update(b"trnm.domain.hash.v1");
        for frame in [
            JOURNAL_SCHEMA_OBJECTS_DIGEST_DOMAIN_V0,
            &JOURNAL_SCHEMA_VERSION_V6.to_be_bytes(),
            &JOURNAL_SAFETY_SCHEMA_VERSION_V6.to_be_bytes(),
            &u64::try_from(objects.len())
                .expect("schema object count fits u64")
                .to_be_bytes(),
        ] {
            hasher.update(
                u64::try_from(frame.len())
                    .expect("schema digest frame length fits u64")
                    .to_be_bytes(),
            );
            hasher.update(frame);
        }
        for ((kind, name), sql) in objects {
            for frame in [kind.as_bytes(), name.as_bytes(), sql.as_bytes()] {
                hasher.update(
                    u64::try_from(frame.len())
                        .expect("schema object frame length fits u64")
                        .to_be_bytes(),
                );
                hasher.update(frame);
            }
        }
        hasher.finalize().into()
    }

    // Frozen historical DDL. These are deliberately not generated from the
    // current schema: changing current text must never silently rewrite what a
    // test means by a v2, v3, v4, or v5 journal image.
    const HISTORICAL_JOURNAL_SCHEMA_SQL_V5: &str = "
        CREATE TABLE safety_store_metadata_v0 (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            journal_schema INTEGER NOT NULL CHECK(journal_schema=5),
            journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
            core_record_codec INTEGER NOT NULL CHECK(core_record_codec=0),
            safety_schema INTEGER NOT NULL CHECK(safety_schema=11),
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

    const HISTORICAL_JOURNAL_SCHEMA_SQL_V4: &str = "
        CREATE TABLE safety_store_metadata_v0 (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            journal_schema INTEGER NOT NULL CHECK(journal_schema=4),
            journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
            core_record_codec INTEGER NOT NULL CHECK(core_record_codec=0),
            safety_schema INTEGER NOT NULL CHECK(safety_schema=10),
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

    const HISTORICAL_JOURNAL_SCHEMA_SQL_V3: &str = "
        CREATE TABLE safety_store_metadata_v0 (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            journal_schema INTEGER NOT NULL CHECK(journal_schema=3),
            journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
            core_record_codec INTEGER NOT NULL CHECK(core_record_codec=0),
            safety_schema INTEGER NOT NULL CHECK(safety_schema=9),
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

    const HISTORICAL_JOURNAL_SCHEMA_SQL_V2: &str = "
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

    #[test]
    fn journal_v6_with_safety_schema_v12_is_the_only_canonical_schema() {
        let connection = Connection::open_in_memory().expect("open current schema fixture");
        connection
            .execute_batch(JOURNAL_SCHEMA_SQL_V6)
            .expect("install current journal-v6 schema");

        assert!(validate_canonical_schema(&connection).is_ok());
        assert_eq!(JOURNAL_SCHEMA_VERSION_V6, 6);
        assert_eq!(JOURNAL_SAFETY_SCHEMA_VERSION_V6, 12);
    }

    #[test]
    fn journal_v6_sqlite_schema_objects_have_a_frozen_digest() {
        let connection = Connection::open_in_memory().expect("open frozen schema fixture");
        connection
            .execute_batch(JOURNAL_SCHEMA_SQL_V6)
            .expect("install frozen journal-v6 schema");
        assert_eq!(
            canonical_schema_objects_digest_v0(&connection),
            [
                244, 143, 230, 111, 99, 95, 50, 87, 237, 242, 154, 240, 24, 237, 167, 198, 183,
                196, 214, 146, 210, 183, 138, 135, 107, 41, 157, 167, 161, 46, 188, 145,
            ],
        );
    }

    #[test]
    fn journal_v5_with_safety_schema_v11_is_not_implicitly_migrated() {
        let connection = Connection::open_in_memory().expect("open historical schema fixture");
        connection
            .execute_batch(HISTORICAL_JOURNAL_SCHEMA_SQL_V5)
            .expect("install historical journal-v5 schema");

        assert!(matches!(
            validate_canonical_schema(&connection),
            Err(SafetyStoreErrorV0::SchemaMismatch)
        ));
    }

    #[test]
    fn journal_v4_with_safety_schema_v10_is_not_implicitly_migrated() {
        let connection = Connection::open_in_memory().expect("open historical schema fixture");
        connection
            .execute_batch(HISTORICAL_JOURNAL_SCHEMA_SQL_V4)
            .expect("install historical journal-v4 schema");

        assert!(matches!(
            validate_canonical_schema(&connection),
            Err(SafetyStoreErrorV0::SchemaMismatch)
        ));
    }

    #[test]
    fn journal_v3_with_safety_schema_v9_is_not_implicitly_migrated() {
        let connection = Connection::open_in_memory().expect("open historical schema fixture");
        connection
            .execute_batch(HISTORICAL_JOURNAL_SCHEMA_SQL_V3)
            .expect("install historical journal-v3 schema");

        assert!(matches!(
            validate_canonical_schema(&connection),
            Err(SafetyStoreErrorV0::SchemaMismatch)
        ));
    }

    #[test]
    fn journal_v2_with_safety_schema_v8_is_not_implicitly_migrated() {
        let connection = Connection::open_in_memory().expect("open historical schema fixture");
        connection
            .execute_batch(HISTORICAL_JOURNAL_SCHEMA_SQL_V2)
            .expect("install historical journal-v2 schema");

        assert!(matches!(
            validate_canonical_schema(&connection),
            Err(SafetyStoreErrorV0::SchemaMismatch)
        ));
    }
}
