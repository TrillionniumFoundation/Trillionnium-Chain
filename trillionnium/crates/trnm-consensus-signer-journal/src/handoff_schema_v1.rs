use std::collections::BTreeMap;

use rusqlite::Connection;

use crate::HandoffSignerJournalErrorV1;

pub(crate) const JOURNAL_SCHEMA_VERSION_V1: u16 = 1;
pub(crate) const MAXIMUM_SQL_INTENT_BYTES_V1: usize = 16 * 1024;

pub(crate) const JOURNAL_SCHEMA_SQL_V1: &str = "
    CREATE TABLE handoff_signer_metadata_v1 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        journal_schema INTEGER NOT NULL CHECK(journal_schema=1),
        journal_id BLOB NOT NULL CHECK(length(journal_id)=32),
        genesis_hash BLOB NOT NULL CHECK(length(genesis_hash)=32),
        chain_id BLOB NOT NULL CHECK(length(chain_id)>0 AND length(chain_id)<=128),
        old_epoch_be BLOB NOT NULL CHECK(length(old_epoch_be)=8),
        new_epoch_be BLOB NOT NULL CHECK(length(new_epoch_be)=8),
        old_protocol_version_be BLOB NOT NULL CHECK(length(old_protocol_version_be)=4),
        new_protocol_version_be BLOB NOT NULL CHECK(length(new_protocol_version_be)=4),
        old_validator_set_id BLOB NOT NULL CHECK(length(old_validator_set_id)=32),
        new_validator_set_id BLOB NOT NULL CHECK(length(new_validator_set_id)=32),
        old_validator_set_cev0 BLOB NOT NULL
            CHECK(length(old_validator_set_cev0)>0 AND length(old_validator_set_cev0)<=32768),
        new_validator_set_cev0 BLOB NOT NULL
            CHECK(length(new_validator_set_cev0)>0 AND length(new_validator_set_cev0)<=32768),
        old_parameters_hash BLOB NOT NULL CHECK(length(old_parameters_hash)=32),
        new_parameters_hash BLOB NOT NULL CHECK(length(new_parameters_hash)=32),
        old_parameters_cev0 BLOB NOT NULL CHECK(length(old_parameters_cev0)=341),
        new_parameters_cev0 BLOB NOT NULL CHECK(length(new_parameters_cev0)=341),
        author BLOB NOT NULL CHECK(length(author)>0 AND length(author)<=128),
        old_author_public_key BLOB NOT NULL CHECK(length(old_author_public_key)=32),
        signer_profile_ref BLOB NOT NULL CHECK(length(signer_profile_ref)=32),
        external_watermark_scope BLOB NOT NULL CHECK(length(external_watermark_scope)=32),
        maximum_intents_be BLOB NOT NULL CHECK(length(maximum_intents_be)=8),
        maximum_intent_bytes_be BLOB NOT NULL CHECK(length(maximum_intent_bytes_be)=8),
        maximum_database_bytes_be BLOB NOT NULL CHECK(length(maximum_database_bytes_be)=8),
        profile_checksum BLOB NOT NULL CHECK(length(profile_checksum)=32),
        metadata_checksum BLOB NOT NULL CHECK(length(metadata_checksum)=32)
    ) STRICT;
    CREATE TABLE signer_intents_v1 (
        fingerprint BLOB PRIMARY KEY NOT NULL CHECK(length(fingerprint)=32),
        intent_class INTEGER NOT NULL CHECK(intent_class IN (0, 1)),
        signing_root BLOB NOT NULL CHECK(length(signing_root)=32),
        canonical_intent BLOB NOT NULL
            CHECK(length(canonical_intent)>0 AND length(canonical_intent)<=16384),
        intent_checksum BLOB NOT NULL CHECK(length(intent_checksum)=32),
        epoch_be BLOB CHECK(epoch_be IS NULL OR length(epoch_be)=8),
        view_be BLOB CHECK(view_be IS NULL OR length(view_be)=8),
        intent_kind INTEGER CHECK(intent_kind IS NULL OR intent_kind IN (1, 2)),
        safety_revision_be BLOB CHECK(
            safety_revision_be IS NULL OR length(safety_revision_be)=8
        ),
        genesis_hash BLOB CHECK(genesis_hash IS NULL OR length(genesis_hash)=32),
        old_epoch_be BLOB CHECK(old_epoch_be IS NULL OR length(old_epoch_be)=8),
        new_epoch_be BLOB CHECK(new_epoch_be IS NULL OR length(new_epoch_be)=8),
        handoff_role INTEGER CHECK(handoff_role IS NULL OR handoff_role IN (0, 1)),
        validator_id BLOB CHECK(
            validator_id IS NULL OR (length(validator_id)>0 AND length(validator_id)<=128)
        ),
        descriptor_digest BLOB CHECK(
            descriptor_digest IS NULL OR length(descriptor_digest)=32
        ),
        descriptor_cev0 BLOB,
        admission_digest BLOB CHECK(
            admission_digest IS NULL OR length(admission_digest)=32
        ),
        CHECK(
            (intent_class=0
                AND epoch_be IS NOT NULL AND view_be IS NOT NULL
                AND intent_kind IS NOT NULL AND safety_revision_be IS NOT NULL
                AND genesis_hash IS NULL AND old_epoch_be IS NULL AND new_epoch_be IS NULL
                AND handoff_role IS NULL AND validator_id IS NULL
                AND descriptor_digest IS NULL AND descriptor_cev0 IS NULL
                AND admission_digest IS NULL)
            OR
            (intent_class=1
                AND epoch_be IS NULL AND view_be IS NULL
                AND intent_kind IS NULL AND safety_revision_be IS NULL
                AND genesis_hash IS NOT NULL AND old_epoch_be IS NOT NULL
                AND new_epoch_be IS NOT NULL AND handoff_role IS NOT NULL
                AND validator_id IS NOT NULL AND descriptor_digest IS NOT NULL
                AND descriptor_cev0 IS NOT NULL
                AND length(descriptor_cev0)>0 AND length(descriptor_cev0)<=1024
                AND admission_digest IS NOT NULL)
        )
    ) STRICT;
    CREATE UNIQUE INDEX signer_consensus_round_unique_v1
        ON signer_intents_v1(epoch_be, view_be, intent_kind)
        WHERE intent_class=0;
    CREATE UNIQUE INDEX signer_safety_revision_unique_v1
        ON signer_intents_v1(safety_revision_be)
        WHERE intent_class=0;
    CREATE UNIQUE INDEX signer_handoff_transition_role_unique_v1
        ON signer_intents_v1(
            genesis_hash, old_epoch_be, new_epoch_be, handoff_role, validator_id
        ) WHERE intent_class=1;
    CREATE TABLE signer_events_v1 (
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
        FOREIGN KEY(fingerprint) REFERENCES signer_intents_v1(fingerprint)
    ) STRICT;
    CREATE TABLE signer_head_v1 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        active_sequence_be BLOB NOT NULL CHECK(length(active_sequence_be)=8),
        active_chain_checksum BLOB NOT NULL CHECK(length(active_chain_checksum)=32),
        head_checksum BLOB NOT NULL CHECK(length(head_checksum)=32)
    ) STRICT;
    CREATE TABLE signer_accounting_v1 (
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
        )
    ) STRICT;
    CREATE TABLE terminal_old_epoch_fence_v1 (
        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
        genesis_hash BLOB NOT NULL CHECK(length(genesis_hash)=32),
        old_epoch_be BLOB NOT NULL CHECK(length(old_epoch_be)=8),
        new_epoch_be BLOB NOT NULL CHECK(length(new_epoch_be)=8),
        validator_id BLOB NOT NULL CHECK(length(validator_id)>0 AND length(validator_id)<=128),
        descriptor_digest BLOB NOT NULL CHECK(length(descriptor_digest)=32),
        fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
        signature_sequence_be BLOB NOT NULL CHECK(length(signature_sequence_be)=8),
        fence_checksum BLOB NOT NULL CHECK(length(fence_checksum)=32),
        FOREIGN KEY(fingerprint) REFERENCES signer_intents_v1(fingerprint),
        FOREIGN KEY(signature_sequence_be) REFERENCES signer_events_v1(sequence_be)
    ) STRICT;
    CREATE TRIGGER handoff_metadata_no_update_v1
        BEFORE UPDATE ON handoff_signer_metadata_v1
        BEGIN SELECT RAISE(ABORT, 'schema1 metadata is immutable'); END;
    CREATE TRIGGER handoff_metadata_no_delete_v1
        BEFORE DELETE ON handoff_signer_metadata_v1
        BEGIN SELECT RAISE(ABORT, 'schema1 metadata is immutable'); END;
    CREATE TRIGGER signer_intents_no_update_v1
        BEFORE UPDATE ON signer_intents_v1
        BEGIN SELECT RAISE(ABORT, 'schema1 intents are append-only'); END;
    CREATE TRIGGER signer_intents_no_delete_v1
        BEFORE DELETE ON signer_intents_v1
        BEGIN SELECT RAISE(ABORT, 'schema1 intents are append-only'); END;
    CREATE TRIGGER terminal_fence_blocks_consensus_prepare_v1
        BEFORE INSERT ON signer_intents_v1
        WHEN NEW.intent_class=0 AND EXISTS(
            SELECT 1 FROM terminal_old_epoch_fence_v1 WHERE singleton=1
        )
        BEGIN SELECT RAISE(ABORT, 'terminal old-epoch fence blocks consensus prepare'); END;
    CREATE TRIGGER signer_events_no_update_v1
        BEFORE UPDATE ON signer_events_v1
        BEGIN SELECT RAISE(ABORT, 'schema1 events are append-only'); END;
    CREATE TRIGGER signer_events_no_delete_v1
        BEFORE DELETE ON signer_events_v1
        BEGIN SELECT RAISE(ABORT, 'schema1 events are append-only'); END;
    CREATE TRIGGER signer_events_single_pending_v1
        BEFORE INSERT ON signer_events_v1
        WHEN NEW.event_kind=0 AND EXISTS(
            SELECT 1
            FROM signer_events_v1 AS prepared
            LEFT JOIN signer_events_v1 AS signed
              ON signed.fingerprint=prepared.fingerprint AND signed.event_kind=1
            WHERE prepared.event_kind=0 AND signed.fingerprint IS NULL
        )
        BEGIN SELECT RAISE(ABORT, 'schema1 permits only one global pending intent'); END;
    CREATE TRIGGER signer_signed_consumes_pending_v1
        BEFORE INSERT ON signer_events_v1
        WHEN NEW.event_kind=1 AND (
            NOT EXISTS(
                SELECT 1 FROM signer_events_v1 AS prepared
                WHERE prepared.fingerprint=NEW.fingerprint AND prepared.event_kind=0
            ) OR EXISTS(
                SELECT 1
                FROM signer_events_v1 AS prepared
                LEFT JOIN signer_events_v1 AS signed
                  ON signed.fingerprint=prepared.fingerprint AND signed.event_kind=1
                WHERE prepared.event_kind=0 AND signed.fingerprint IS NULL
                  AND prepared.fingerprint<>NEW.fingerprint
            )
        )
        BEGIN SELECT RAISE(ABORT, 'schema1 signature must consume the unique pending intent'); END;
    CREATE TRIGGER signer_head_no_delete_v1
        BEFORE DELETE ON signer_head_v1
        BEGIN SELECT RAISE(ABORT, 'schema1 head cannot be deleted'); END;
    CREATE TRIGGER signer_accounting_no_delete_v1
        BEFORE DELETE ON signer_accounting_v1
        BEGIN SELECT RAISE(ABORT, 'schema1 accounting cannot be deleted'); END;
    CREATE TRIGGER terminal_fence_no_update_v1
        BEFORE UPDATE ON terminal_old_epoch_fence_v1
        BEGIN SELECT RAISE(ABORT, 'terminal old-epoch fence is immutable'); END;
    CREATE TRIGGER terminal_fence_no_delete_v1
        BEFORE DELETE ON terminal_old_epoch_fence_v1
        BEGIN SELECT RAISE(ABORT, 'terminal old-epoch fence is immutable'); END;
    CREATE TRIGGER terminal_fence_requires_signed_old_handoff_v1
        BEFORE INSERT ON terminal_old_epoch_fence_v1
        WHEN NOT EXISTS(
            SELECT 1
            FROM signer_intents_v1 AS intent
            JOIN signer_events_v1 AS event
              ON event.fingerprint=intent.fingerprint
            WHERE intent.fingerprint=NEW.fingerprint
              AND intent.intent_class=1
              AND intent.handoff_role=0
              AND intent.genesis_hash=NEW.genesis_hash
              AND intent.old_epoch_be=NEW.old_epoch_be
              AND intent.new_epoch_be=NEW.new_epoch_be
              AND intent.validator_id=NEW.validator_id
              AND intent.descriptor_digest=NEW.descriptor_digest
              AND event.sequence_be=NEW.signature_sequence_be
              AND event.event_kind=1
              AND event.signature IS NOT NULL
        )
        BEGIN SELECT RAISE(ABORT, 'terminal fence requires matching signed old handoff'); END;
";

pub(crate) fn validate_canonical_schema_v1(
    connection: &Connection,
) -> Result<(), HandoffSignerJournalErrorV1> {
    let canonical = Connection::open_in_memory()
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("open canonical schema1", error))?;
    canonical
        .execute_batch(JOURNAL_SCHEMA_SQL_V1)
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("install canonical schema1", error))?;
    if schema_objects_v1(connection)? != schema_objects_v1(&canonical)? {
        return Err(HandoffSignerJournalErrorV1::SchemaMismatch);
    }
    Ok(())
}

fn schema_objects_v1(
    connection: &Connection,
) -> Result<BTreeMap<(String, String), String>, HandoffSignerJournalErrorV1> {
    let mut statement = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("prepare schema1 allowlist", error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(|error| HandoffSignerJournalErrorV1::sqlite("query schema1 allowlist", error))?;
    let mut objects = BTreeMap::new();
    for row in rows {
        let (kind, name, sql) = row.map_err(|error| {
            HandoffSignerJournalErrorV1::sqlite("read schema1 allowlist", error)
        })?;
        let sql = sql
            .ok_or(HandoffSignerJournalErrorV1::SchemaMismatch)?
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if objects.insert((kind, name), sql).is_some() {
            return Err(HandoffSignerJournalErrorV1::SchemaMismatch);
        }
    }
    Ok(objects)
}
