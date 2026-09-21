//! Bounded source inventory audit for the schema-10 historical replay base.
//!
//! This module is comparison-only.  It does not construct an owner capability,
//! migrate the database, or treat a source digest as execution authority.

use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use rusqlite::{types::ValueRef, Connection};
use sha2::{Digest, Sha256};
use trnm_native_application::ApplicationHeadV0;

use crate::poco_preparation_journal::{
    poco_preparation_sidecar_path_v0, HistoricalReplayPreparationInventoryV1,
    PocoPreparationJournalV0,
};

const MAX_SOURCE_ROWS: usize = 128;
const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024 * 1024;

// This is deliberately the complete schema-10 source allowlist, including
// legacy tables retained during the later-schema migrations.
const SOURCE_TABLES: &[&str] = &[
    "native_application_metadata_v0",
    "native_durable_execution_p_v0",
    "native_h1_state_sync_trusted_base_v0",
    "native_epoch_edge_v1",
    "native_durable_execution_p_v1",
    "native_application_epoch_context_v1",
    "native_later_epoch_finality_v1",
    "native_later_epoch_edge_v1",
    "native_later_epoch_application_finality_v1",
    "native_later_epoch_descendant_finality_v1",
];

fn quote(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

/// Screen sqlite_schema before the existing exact schema SQL is copied.
pub(super) fn screen_source_schema_v1(connection: &Connection) -> Result<()> {
    let (count, bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(CAST(name AS BLOB))+length(CAST(tbl_name AS BLOB))+COALESCE(length(CAST(sql AS BLOB)),0)),0) FROM sqlite_schema",
        [], |row| Ok((row.get(0)?,row.get(1)?)),
    )?;
    ensure!(
        (0..=64).contains(&count) && (0..=524288).contains(&bytes),
        "historical source schema resource bound"
    );
    Ok(())
}

fn column_check(table: &str, column: &str) -> String {
    let q = quote(column);
    if column == "chain_id" {
        return format!("typeof({q})='text' AND length(CAST({q} AS BLOB)) BETWEEN 1 AND 128");
    }
    if matches!(
        column,
        "singleton" | "phase" | "artifact_kind" | "parent_kind"
    ) || (column == "status" && table == "native_durable_execution_p_v1")
    {
        return format!("typeof({q})='integer'");
    }
    let (minimum, maximum) = match column {
        "authenticated_snapshot" | "target_snapshot" => (1, 256 * 1024 * 1024),
        "replay_command_ids"
        | "replay_signer_nonces"
        | "target_replay_command_ids"
        | "target_replay_signer_nonces"
        | "replay_commands"
        | "replay_nonces" => (4, 16 * 1024 * 1024),
        "artifact" => (1, 16 * 1024 * 1024),
        "target_lifecycle_json" | "lifecycle" => (1, 1024 * 1024),
        "evidence" => (1, crate::epoch_recovery::MAX_EPOCH_EVIDENCE_BYTES_V1),
        "proof" | "checkpoint_finality" | "anchor_kernel" => (1, 8 * 1024 * 1024),
        "target_set" | "active_set" | "new_validator_set" => (1, 1024 * 1024),
        "header"
        | "checkpoint_parent_header"
        | "checkpoint_header"
        | "next_epoch_commitment"
        | "target_parameters"
        | "active_parameters"
        | "new_parameters" => (1, 4096),
        "edge_lineage" => (4, 4 + 32 * 32),
        "schema_version"
        | "durable_sequence"
        | "head_height"
        | "target_height"
        | "p_sequence"
        | "status"
        | "parent_height"
        | "commit_sequence"
        | "checkpoint_commit_sequence"
        | "checkpoint_height"
        | "terminal_height"
        | "first_height"
        | "consumed_sequence"
        | "head_commit_sequence"
        | "consensus_parent_height"
        | "install_sequence" => (8, 8),
        _ => (32, 32), // Remaining exact schema columns are fixed H32 identities.
    };
    let present = format!("typeof({q})='blob' AND length({q}) BETWEEN {minimum} AND {maximum}");
    let nullable = match table {
        "native_durable_execution_p_v0" => matches!(column, "commit_sequence" | "commit_id"),
        "native_durable_execution_p_v1" => {
            matches!(column, "parent_p_digest" | "commit_sequence" | "commit_id")
        }
        "native_epoch_edge_v1" | "native_later_epoch_edge_v1" => {
            matches!(column, "consumed_block" | "consumed_sequence")
        }
        _ => false,
    };
    if nullable {
        format!("{q} IS NULL OR ({present})")
    } else {
        present
    }
}

fn table_columns(connection: &Connection, table: &str) -> Result<(Vec<String>, Vec<String>)> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({})", quote(table)))?;
    let mut rows = statement.query([])?;
    let mut columns = Vec::new();
    let mut primary = Vec::new();
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        let primary_index: i64 = row.get(5)?;
        columns.push(name.clone());
        if primary_index > 0 {
            primary.push((primary_index, name));
        }
    }
    ensure!(
        !columns.is_empty(),
        "historical source table is missing: {table}"
    );
    primary.sort_by_key(|(index, _)| *index);
    let primary = if primary.is_empty() {
        columns.clone()
    } else {
        primary.into_iter().map(|(_, name)| name).collect()
    };
    Ok((columns, primary))
}

fn screen_table(
    connection: &Connection,
    table: &str,
) -> Result<(usize, usize, Vec<String>, Vec<String>)> {
    let (columns, primary) = table_columns(connection, table)?;
    let expressions = columns
        .iter()
        .map(|column| {
            let q = quote(column);
            format!(
                "CASE WHEN typeof({q})='blob' THEN length({q})
                      WHEN typeof({q})='text' THEN length(CAST({q} AS BLOB))
                      ELSE 0 END"
            )
        })
        .collect::<Vec<_>>();
    let invalid = columns
        .iter()
        .map(|column| {
            format!(
                "CASE WHEN {} THEN 0 ELSE 1 END",
                column_check(table, column)
            )
        })
        .collect::<Vec<_>>();
    let sql = format!(
        "SELECT COUNT(*), COALESCE(SUM({}),0), COALESCE(SUM({}),0) FROM {}",
        expressions.join("+"),
        invalid.join("+"),
        quote(table)
    );
    let (count, bytes, invalid): (i64, i64, i64) =
        connection.query_row(&sql, [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    ensure!(
        count >= 0 && count as usize <= MAX_SOURCE_ROWS,
        "historical source row bound: {table}"
    );
    ensure!(
        invalid == 0,
        "historical source column type/length bound: {table}"
    );
    ensure!(bytes >= 0, "historical source byte overflow: {table}");
    ensure!(
        bytes as u64 <= MAX_SOURCE_BYTES as u64,
        "historical source byte bound: {table}"
    );
    Ok((count as usize, bytes as usize, columns, primary))
}

fn hash_value(hasher: &mut Sha256, value: ValueRef<'_>) -> Result<()> {
    match value {
        ValueRef::Null => {
            hasher.update([0]);
            hasher.update(0u64.to_be_bytes());
        }
        ValueRef::Integer(value) => {
            hasher.update([1]);
            hasher.update(8u64.to_be_bytes());
            hasher.update(value.to_be_bytes());
        }
        ValueRef::Real(_) => bail!("historical source REAL value is not canonical"),
        ValueRef::Text(value) => {
            hasher.update([3]);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
        ValueRef::Blob(value) => {
            hasher.update([4]);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
    }
    Ok(())
}

/// Run only the allocation/type/count screen.  Callers should invoke this
/// before any high-level source row loader.
pub(super) fn screen_source_inventory_v1(connection: &Connection) -> Result<()> {
    let mut total = 0usize;
    let mut p_count = 0;
    for table in SOURCE_TABLES {
        let (count, bytes, _, _) = screen_table(connection, table)?;
        if matches!(
            *table,
            "native_durable_execution_p_v0" | "native_durable_execution_p_v1"
        ) {
            p_count += count;
            ensure!(
                p_count <= MAX_SOURCE_ROWS,
                "historical combined P row bound"
            );
        }
        total = total
            .checked_add(bytes)
            .context("historical source byte count overflow")?;
        ensure!(
            total <= MAX_SOURCE_BYTES,
            "historical source total byte bound"
        );
    }
    Ok(())
}

/// Hash the exact typed rows of the audited source and the independently
/// audited preparation journal.  The caller must perform the schema-10,
/// metadata, P/edge, and M01 lineage audits before treating this digest as a
/// source pin; this function itself never promotes a row to authority.
pub(super) fn audit_source_inventory_v1(
    connection: &Connection,
    application_path: &Path,
    anchor: &ApplicationHeadV0,
) -> Result<[u8; 32]> {
    screen_source_inventory_v1(connection)?;

    let mut hasher = Sha256::new();
    hasher.update(b"trnm.native.historical-replay-source-inventory.v1");
    hasher.update((SOURCE_TABLES.len() as u64).to_be_bytes());
    for table in SOURCE_TABLES {
        let (count, _, columns, primary) = screen_table(connection, table)?;
        hasher.update(b"table");
        hasher.update((table.len() as u64).to_be_bytes());
        hasher.update(table.as_bytes());
        hasher.update((count as u64).to_be_bytes());
        hasher.update((columns.len() as u64).to_be_bytes());
        let quoted = columns
            .iter()
            .map(|column| quote(column))
            .collect::<Vec<_>>();
        let sql = format!(
            "SELECT {} FROM {} ORDER BY {}",
            quoted.join(","),
            quote(table),
            primary
                .iter()
                .map(|column| quote(column))
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut statement = connection.prepare(&sql)?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            for (index, column) in columns.iter().enumerate() {
                hasher.update((column.len() as u64).to_be_bytes());
                hasher.update(column.as_bytes());
                hash_value(&mut hasher, row.get_ref(index)?)?;
            }
        }
    }

    let metadata_matches: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM native_application_metadata_v0
             WHERE singleton=1 AND typeof(head_height)='blob' AND length(head_height)=8
               AND head_height=?1 AND typeof(head_block_id)='blob' AND length(head_block_id)=32
               AND head_block_id=?2 AND typeof(head_state_root)='blob' AND length(head_state_root)=32
               AND head_state_root=?3 AND head_commit_id=?4)",
        rusqlite::params![
            anchor.height().get().to_be_bytes().as_slice(),
            anchor.block_id().as_bytes().as_slice(),
            anchor.state_root().as_bytes().as_slice(),
            anchor.commit_id().as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    ensure!(
        metadata_matches,
        "historical source anchor metadata mismatch"
    );

    let journal = PocoPreparationJournalV0::open_existing(poco_preparation_sidecar_path_v0(
        application_path,
    ))?;
    let HistoricalReplayPreparationInventoryV1 { digest, facts } =
        journal.audit_historical_source_v1()?;
    // Original legacy checkpoint evidence explicitly names its preparation.
    // Later checkpoints/ordinary P do not have such a record; never invent one.
    let mut legacy =
        connection.prepare("SELECT evidence FROM native_epoch_edge_v1 ORDER BY binding")?;
    let mut rows = legacy.query([])?;
    while let Some(row) = rows.next()? {
        let evidence = match row.get_ref(0)? {
            ValueRef::Blob(bytes) => crate::epoch_recovery::EpochRecoveryEvidenceV1::decode(bytes)?,
            _ => bail!("historical legacy evidence type"),
        };
        let header_digest: [u8; 32] = Sha256::digest(&evidence.checkpoint_header).into();
        ensure!(
            facts
                .iter()
                .any(|fact| fact.preparation_id == evidence.preparation_id
                    && fact.phase == 1
                    && fact.bound_header_digest == Some(header_digest)),
            "historical legacy checkpoint lacks exact retained preparation"
        );
    }
    // Future application reservations are always unresolved for this source.
    // A bound seal can be retained only if it exactly belongs to the already
    // audited source's final checkpoint proof. No caller allowlist is accepted.
    let future = facts
        .iter()
        .filter(|fact| fact.height > anchor.height().get())
        .collect::<Vec<_>>();
    let allowed_seals = if future.is_empty() {
        std::collections::BTreeSet::new()
    } else {
        source_seals_v1(connection, anchor.height().get())?
    };
    hasher.update(b"preparation-journal");
    hasher.update(digest);
    for fact in facts {
        if fact.height > anchor.height().get() {
            ensure!(
                fact.phase == 1,
                "unresolved historical preparation above source anchor"
            );
            let header = fact
                .bound_header_digest
                .context("historical preparation above anchor lacks bound header")?;
            ensure!(
                allowed_seals.contains(&(fact.height, header)),
                "historical preparation above anchor is not an exact source seal"
            );
        }
        hasher.update(fact.preparation_id);
        hasher.update(fact.height.to_be_bytes());
        hasher.update([fact.phase]);
        if let Some(header) = fact.bound_header_digest {
            hasher.update([1]);
            hasher.update(header);
        } else {
            hasher.update([0]);
        }
    }
    Ok(hasher.finalize().into())
}

fn source_seals_v1(
    connection: &Connection,
    height: u64,
) -> Result<std::collections::BTreeSet<(u64, [u8; 32])>> {
    // An admitted source anchor is a genuine v1 P. Only its installed later
    // checkpoint edge can retain seals strictly above the application head.
    let mut statement = connection.prepare(
        "SELECT f.checkpoint_finality,f.next_epoch_commitment,f.checkpoint_parent_header,p.target_set,p.target_parameters
         FROM native_later_epoch_finality_v1 f
         JOIN native_durable_execution_p_v1 p ON p.block_id=f.checkpoint_block
         JOIN native_later_epoch_edge_v1 e ON e.checkpoint_block=f.checkpoint_block
         WHERE p.target_height=?1 AND p.status=1 AND e.phase=0",
    )?;
    let mut rows = statement.query([height.to_be_bytes().as_slice()])?;
    let mut result = std::collections::BTreeSet::new();
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        ensure!(count == 1, "historical source seal proof ambiguity");
        let blob = |column| -> Result<&[u8]> {
            match row.get_ref(column)? {
                ValueRef::Blob(bytes) => Ok(bytes),
                _ => bail!("historical source seal preimage type"),
            }
        };
        let set = trnm_consensus_types::decode_validator_set_v0_exact(blob(3)?)
            .map_err(|e| anyhow::anyhow!("source seal set: {e:?}"))?;
        let parameters = trnm_consensus_types::decode_consensus_parameters_v0_exact(blob(4)?)
            .map_err(|e| anyhow::anyhow!("source seal parameters: {e:?}"))?;
        let commitment = trnm_consensus_types::decode_next_epoch_commitment_v0_exact(blob(1)?)
            .map_err(|e| anyhow::anyhow!("source seal commitment: {e:?}"))?;
        let parent = trnm_consensus_types::decode_block_header_v0_exact(blob(2)?)
            .map_err(|e| anyhow::anyhow!("source seal parent: {e:?}"))?;
        let proof = trnm_consensus_types::decode_checkpoint_finality_proof_v0_exact(
            blob(0)?,
            &set,
            &parameters,
            &commitment,
            parent.timestamp_ms(),
        )
        .map_err(|e| anyhow::anyhow!("source seal proof: {e:?}"))?;
        ensure!(
            proof.finalized_block().header().height().get() == height,
            "source seal checkpoint height"
        );
        for header in [proof.child().header(), proof.grandchild().header()] {
            let bytes = header
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("source seal header: {e:?}"))?;
            result.insert((header.height().get(), Sha256::digest(bytes).into()));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_source_screen_rejects_oversized_and_wrong_typed_columns() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE native_durable_execution_p_v1(block_id BLOB PRIMARY KEY,header BLOB,replay_commands BLOB,commit_sequence BLOB,status INTEGER); INSERT INTO native_durable_execution_p_v1 VALUES(zeroblob(32),zeroblob(4096),zeroblob(4),NULL,0)").unwrap();
        let table = "native_durable_execution_p_v1";
        assert_eq!(screen_table(&connection, table).unwrap().0, 1);
        for mutant in [
            "header=zeroblob(4097)",
            "header=CAST(zeroblob(4096) AS TEXT)",
            "header=NULL",
            "block_id=zeroblob(33)",
            "block_id=17",
            "replay_commands=zeroblob(16777217)",
            "replay_commands=zeroblob(3)",
            "commit_sequence=zeroblob(9)",
            "commit_sequence=17",
            "status=0.5",
        ] {
            connection.execute_batch("SAVEPOINT mutant").unwrap();
            connection
                .execute(&format!("UPDATE {table} SET {mutant}"), [])
                .unwrap();
            assert!(screen_table(&connection, table).is_err(), "{mutant}");
            connection
                .execute_batch("ROLLBACK TO mutant; RELEASE mutant")
                .unwrap();
        }
        connection.execute_batch("CREATE TABLE native_application_metadata_v0(singleton INTEGER,chain_id TEXT); INSERT INTO native_application_metadata_v0 VALUES(1,'ok')").unwrap();
        assert!(screen_table(&connection, "native_application_metadata_v0").is_ok());
        connection
            .execute(
                "UPDATE native_application_metadata_v0 SET chain_id=CAST(zeroblob(129) AS TEXT)",
                [],
            )
            .unwrap();
        assert!(screen_table(&connection, "native_application_metadata_v0").is_err());
    }

    #[test]
    fn historical_source_screen_caps_combined_p_and_schema_inventory() {
        let connection = Connection::open_in_memory().unwrap();
        for table in SOURCE_TABLES {
            connection
                .execute(&format!("CREATE TABLE {table}(id BLOB PRIMARY KEY)"), [])
                .unwrap();
        }
        for index in 0u64..=64 {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&index.to_be_bytes());
            connection
                .execute(
                    "INSERT INTO native_durable_execution_p_v0 VALUES(?)",
                    [id.as_slice()],
                )
                .unwrap();
            if index < 64 {
                connection
                    .execute(
                        "INSERT INTO native_durable_execution_p_v1 VALUES(?)",
                        [id.as_slice()],
                    )
                    .unwrap();
            }
        }
        assert!(screen_source_inventory_v1(&connection).is_err());
        connection
            .execute(
                "DELETE FROM native_durable_execution_p_v0 WHERE id=?",
                [([64u64.to_be_bytes().as_slice(), &[0u8; 24]].concat())],
            )
            .unwrap();
        screen_source_inventory_v1(&connection).unwrap();
        screen_source_schema_v1(&connection).unwrap();
        for index in 0..65 {
            connection
                .execute(&format!("CREATE VIEW extra{index} AS SELECT 1"), [])
                .unwrap();
        }
        assert!(screen_source_schema_v1(&connection).is_err());
    }
}
