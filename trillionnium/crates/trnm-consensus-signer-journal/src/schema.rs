use std::collections::BTreeMap;

use rusqlite::Connection;

use crate::SignerJournalErrorV0;

pub(crate) const JOURNAL_SCHEMA_VERSION_V0: u16 = 0;
pub(crate) const MAXIMUM_SQL_INTENT_BYTES_V0: usize = 16 * 1024;

pub(crate) const JOURNAL_SCHEMA_SQL_V0: &str = "
    CREATE TABLE signer_journal_metadata_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        journal_schema INTEGER NOT NULL CHECK(journal_schema=0),
        journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
        chain_id BLOB NOT NULL CHECK(length(chain_id)>0 AND length(chain_id)<=128),
        protocol_version_be BLOB NOT NULL CHECK(length(protocol_version_be)=4),
        epoch_be BLOB NOT NULL CHECK(length(epoch_be)=8),
        validator_set_id BLOB NOT NULL CHECK(length(validator_set_id)=32),
        genesis_hash BLOB NOT NULL CHECK(length(genesis_hash)=32),
        author BLOB NOT NULL CHECK(length(author)>0 AND length(author)<=128),
        author_public_key BLOB NOT NULL CHECK(length(author_public_key)=32),
        signer_profile_ref BLOB NOT NULL CHECK(length(signer_profile_ref)=32),
        external_watermark_scope BLOB NOT NULL CHECK(length(external_watermark_scope)=32),
        maximum_intents_be BLOB NOT NULL CHECK(length(maximum_intents_be)=8),
        maximum_intent_bytes_be BLOB NOT NULL CHECK(length(maximum_intent_bytes_be)=8),
        maximum_database_bytes_be BLOB NOT NULL CHECK(length(maximum_database_bytes_be)=8),
        profile_checksum BLOB NOT NULL CHECK(length(profile_checksum)=32),
        metadata_checksum BLOB NOT NULL CHECK(length(metadata_checksum)=32)
    ) STRICT;
    CREATE TABLE sign_intents_v0 (
        fingerprint BLOB PRIMARY KEY NOT NULL CHECK(length(fingerprint)=32),
        epoch_be BLOB NOT NULL CHECK(length(epoch_be)=8),
        view_be BLOB NOT NULL CHECK(length(view_be)=8),
        intent_kind INTEGER NOT NULL CHECK(intent_kind IN (0, 1)),
        safety_revision_be BLOB NOT NULL CHECK(length(safety_revision_be)=8),
        signing_root BLOB NOT NULL CHECK(length(signing_root)=32),
        canonical_intent BLOB NOT NULL
            CHECK(length(canonical_intent)>0 AND length(canonical_intent)<=16384),
        intent_checksum BLOB NOT NULL CHECK(length(intent_checksum)=32),
        UNIQUE(epoch_be, view_be, intent_kind),
        UNIQUE(safety_revision_be)
    ) STRICT;
    CREATE TABLE signer_journal_events_v0 (
        sequence_be BLOB PRIMARY KEY NOT NULL
            CHECK(length(sequence_be)=8 AND sequence_be<>x'0000000000000000'),
        event_kind INTEGER NOT NULL CHECK(event_kind IN (0, 1)),
        fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
        signature BLOB CHECK(
            (event_kind=0 AND signature IS NULL) OR
            (event_kind=1 AND length(signature)=64)
        ),
        predecessor_sequence_be BLOB NOT NULL CHECK(length(predecessor_sequence_be)=8),
        predecessor_chain_checksum BLOB NOT NULL CHECK(length(predecessor_chain_checksum)=32),
        event_checksum BLOB NOT NULL CHECK(length(event_checksum)=32),
        chain_checksum BLOB NOT NULL CHECK(length(chain_checksum)=32),
        UNIQUE(fingerprint, event_kind),
        FOREIGN KEY(fingerprint) REFERENCES sign_intents_v0(fingerprint)
    ) STRICT;
    CREATE TABLE signer_journal_head_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        active_sequence_be BLOB NOT NULL CHECK(length(active_sequence_be)=8),
        active_chain_checksum BLOB NOT NULL CHECK(length(active_chain_checksum)=32),
        head_checksum BLOB NOT NULL CHECK(length(head_checksum)=32)
    ) STRICT;
    CREATE TABLE signer_journal_accounting_v0 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        intent_count INTEGER NOT NULL CHECK(intent_count>=0),
        event_count INTEGER NOT NULL CHECK(event_count>=0),
        intent_bytes INTEGER NOT NULL CHECK(intent_bytes>=0),
        maximum_safety_revision_be BLOB CHECK(
            maximum_safety_revision_be IS NULL OR length(maximum_safety_revision_be)=8
        ),
        maximum_vote_view_be BLOB CHECK(
            maximum_vote_view_be IS NULL OR length(maximum_vote_view_be)=8
        ),
        maximum_timeout_view_be BLOB CHECK(
            maximum_timeout_view_be IS NULL OR length(maximum_timeout_view_be)=8
        ),
        CHECK(
            (intent_count=0 AND event_count=0 AND intent_bytes=0
                AND maximum_safety_revision_be IS NULL
                AND maximum_vote_view_be IS NULL
                AND maximum_timeout_view_be IS NULL) OR
            (intent_count>0 AND event_count>=intent_count AND intent_bytes>0
                AND maximum_safety_revision_be IS NOT NULL)
        )
    ) STRICT;
    CREATE TRIGGER signer_metadata_no_update_v0
        BEFORE UPDATE ON signer_journal_metadata_v0
        BEGIN SELECT RAISE(ABORT, 'signer metadata is immutable'); END;
    CREATE TRIGGER signer_metadata_no_delete_v0
        BEFORE DELETE ON signer_journal_metadata_v0
        BEGIN SELECT RAISE(ABORT, 'signer metadata is immutable'); END;
    CREATE TRIGGER sign_intents_no_update_v0
        BEFORE UPDATE ON sign_intents_v0
        BEGIN SELECT RAISE(ABORT, 'sign intents are append-only'); END;
    CREATE TRIGGER sign_intents_no_delete_v0
        BEFORE DELETE ON sign_intents_v0
        BEGIN SELECT RAISE(ABORT, 'sign intents are append-only'); END;
    CREATE TRIGGER signer_events_no_update_v0
        BEFORE UPDATE ON signer_journal_events_v0
        BEGIN SELECT RAISE(ABORT, 'signer events are append-only'); END;
    CREATE TRIGGER signer_events_no_delete_v0
        BEFORE DELETE ON signer_journal_events_v0
        BEGIN SELECT RAISE(ABORT, 'signer events are append-only'); END;
    CREATE TRIGGER signer_head_no_delete_v0
        BEFORE DELETE ON signer_journal_head_v0
        BEGIN SELECT RAISE(ABORT, 'signer head cannot be deleted'); END;
    CREATE TRIGGER signer_accounting_no_delete_v0
        BEFORE DELETE ON signer_journal_accounting_v0
        BEGIN SELECT RAISE(ABORT, 'signer accounting cannot be deleted'); END;
";

pub(crate) fn validate_canonical_schema(
    connection: &Connection,
) -> Result<(), SignerJournalErrorV0> {
    let canonical = Connection::open_in_memory()
        .map_err(|error| SignerJournalErrorV0::sqlite("open canonical schema", error))?;
    canonical
        .execute_batch(JOURNAL_SCHEMA_SQL_V0)
        .map_err(|error| SignerJournalErrorV0::sqlite("install canonical schema", error))?;
    if schema_objects(connection)? != schema_objects(&canonical)? {
        return Err(SignerJournalErrorV0::SchemaMismatch);
    }
    Ok(())
}

fn schema_objects(
    connection: &Connection,
) -> Result<BTreeMap<(String, String), String>, SignerJournalErrorV0> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|error| SignerJournalErrorV0::sqlite("prepare schema allowlist", error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|error| SignerJournalErrorV0::sqlite("query schema allowlist", error))?;
    let mut objects = BTreeMap::new();
    for row in rows {
        let (kind, name, sql) =
            row.map_err(|error| SignerJournalErrorV0::sqlite("read schema allowlist", error))?;
        let sql = sql
            .ok_or(SignerJournalErrorV0::SchemaMismatch)?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if objects.insert((kind, name), sql).is_some() {
            return Err(SignerJournalErrorV0::SchemaMismatch);
        }
    }
    Ok(objects)
}
