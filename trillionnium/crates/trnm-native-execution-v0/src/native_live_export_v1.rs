//! Read-only current-head export. Local records are audited before their
//! leaves are encoded; the result remains inert transport data.
use super::*;
use crate::{NativeCurrentLiveEntryV1, NativeCurrentLiveExportV1};

#[derive(Clone, Copy)]
struct BlobBound {
    name: &'static str,
    minimum: usize,
    maximum: usize,
    nullable: bool,
}

const fn fixed(name: &'static str, width: usize) -> BlobBound {
    BlobBound {
        name,
        minimum: width,
        maximum: width,
        nullable: false,
    }
}

const fn bounded(name: &'static str, maximum: usize) -> BlobBound {
    BlobBound {
        name,
        minimum: 1,
        maximum,
        nullable: false,
    }
}

const fn optional(name: &'static str, width: usize) -> BlobBound {
    BlobBound {
        nullable: true,
        ..fixed(name, width)
    }
}

/// All identifiers and bounds come from code below. SQL only returns scalar
/// statistics, including for malformed TEXT masquerading as a BLOB. This must
/// run inside the same read transaction as the subsequent audited load.
fn screen_blob_table(
    connection: &Connection,
    table: &str,
    maximum_rows: usize,
    maximum_bytes: usize,
    columns: &[BlobBound],
) -> Result<usize> {
    let mut checks = Vec::with_capacity(columns.len());
    let mut sizes = Vec::with_capacity(columns.len());
    for column in columns {
        let name = column.name;
        let present = format!(
            "(typeof({name})='blob' AND length({name}) BETWEEN {} AND {})",
            column.minimum, column.maximum
        );
        checks.push(if column.nullable {
            format!("({name} IS NULL OR {present})")
        } else {
            present
        });
        sizes.push(format!(
            "CASE WHEN typeof({name})='blob' THEN length({name}) ELSE 0 END"
        ));
    }
    let sql = format!(
        "SELECT COUNT(*), COALESCE(SUM({}),0), \
         COALESCE(SUM(CASE WHEN {} THEN 0 ELSE 1 END),0) FROM {table}",
        sizes.join("+"),
        checks.join(" AND ")
    );
    let (count, bytes, invalid): (i64, i64, i64) =
        connection.query_row(&sql, [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    ensure!(
        count >= 0 && count as u64 <= maximum_rows as u64,
        "native export {table} row bound"
    );
    ensure!(
        invalid == 0,
        "native export {table} column type/length bound"
    );
    ensure!(
        bytes >= 0 && bytes as u64 <= maximum_bytes as u64,
        "native export {table} aggregate byte bound"
    );
    Ok(count as usize)
}

/// Export-only availability bounds for the legacy inputs reached by a full
/// schema10 audit. Epoch-v1 variable fields retain their existing stricter
/// readers and fixed fields use borrowed exact-width SQL values. This does not
/// change the legacy owner's write limits or perform a migration.
pub(super) fn screen_legacy_export_inputs(connection: &Connection) -> Result<()> {
    let count = screen_blob_table(
        connection,
        "native_application_metadata_v0",
        1,
        MAX_PREPARED_BYTES,
        &[
            fixed("schema_version", 8),
            fixed("store_id", 32),
            fixed("genesis_hash", 32),
            fixed("chain_descriptor_hash", 32),
            fixed("signer_policy_commitment", 32),
            fixed("validator_set_id", 32),
            fixed("parameters_hash", 32),
            fixed("durable_sequence", 8),
            fixed("head_height", 8),
            fixed("head_block_id", 32),
            fixed("head_state_root", 32),
            fixed("head_commit_id", 32),
            bounded("authenticated_snapshot", MAX_SNAPSHOT_BYTES),
            fixed("authenticated_snapshot_digest", 32),
            bounded("replay_command_ids", MAX_REPLAY_BYTES),
            bounded("replay_signer_nonces", MAX_REPLAY_BYTES),
        ],
    )?;
    ensure!(count == 1, "native export metadata singleton missing");
    let exact: bool = connection.query_row(
        "SELECT typeof(singleton)='integer' AND singleton=1 \
         AND typeof(chain_id)='text' AND length(CAST(chain_id AS BLOB)) BETWEEN 1 AND 128 \
         FROM native_application_metadata_v0",
        [],
        |row| row.get(0),
    )?;
    ensure!(exact, "native export metadata singleton/chain shape");
    screen_blob_table(
        connection,
        "native_durable_execution_p_v0",
        MAX_P_ROWS,
        MAX_PREPARED_BYTES,
        &[
            fixed("block_id", 32),
            fixed("target_height", 8),
            fixed("store_id", 32),
            fixed("p_sequence", 8),
            fixed("status", 8),
            fixed("parent_height", 8),
            fixed("parent_block_id", 32),
            fixed("parent_state_root", 32),
            fixed("parent_commit_id", 32),
            bounded(
                "artifact",
                trnm_native_application::MAX_NATIVE_EXECUTED_BLOCK_ARTIFACT_BYTES_V0,
            ),
            fixed("artifact_digest", 32),
            bounded("target_snapshot", MAX_SNAPSHOT_BYTES),
            fixed("target_snapshot_digest", 32),
            bounded("target_replay_command_ids", MAX_REPLAY_BYTES),
            bounded("target_replay_signer_nonces", MAX_REPLAY_BYTES),
            bounded("target_lifecycle_json", MAX_LIFECYCLE_BYTES),
            fixed("p_digest", 32),
            optional("commit_sequence", 8),
            optional("commit_id", 32),
        ],
    )?;
    screen_blob_table(
        connection,
        "native_h1_state_sync_trusted_base_v0",
        1,
        MAX_PREPARED_BYTES,
        &[
            fixed("store_id", 32),
            fixed("install_sequence", 8),
            fixed("proof_id", 32),
            bounded(
                "artifact",
                trnm_native_application::MAX_NATIVE_EXECUTED_BLOCK_ARTIFACT_BYTES_V0,
            ),
            fixed("artifact_digest", 32),
            fixed("target_snapshot_digest", 32),
            fixed("target_commit_id", 32),
            fixed("import_digest", 32),
        ],
    )?;
    let invalid: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_h1_state_sync_trusted_base_v0 \
         WHERE typeof(singleton)!='integer' OR singleton!=1",
        [],
        |row| row.get(0),
    )?;
    ensure!(invalid == 0, "native export H1 singleton shape");
    Ok(())
}

pub(super) fn fresh_export_metadata(
    path: &Path,
    config: &NativeApplicationConfigV0,
) -> Result<MetadataV0> {
    reject_sqlite_sidecars_v0(path)?;
    let connection = open_immutable_connection_v0(path)?;
    connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
    screen_legacy_export_inputs(&connection)?;
    verify_schema_v0(&connection)?;
    ensure!(
        schema_version(&connection)? == LATER_SCHEMA_VERSION,
        "native export requires explicit schema10"
    );
    let metadata = load_metadata_v0(&connection, config)?;
    validate_metadata_v0(&connection, config, &metadata)?;
    connection.execute_batch("ROLLBACK")?;
    Ok(metadata)
}

impl DurableNativeApplicationV0 {
    /// Export all current committed leaves as inert current-live bytes. The
    /// retained canonical header and strict epoch prefix supply the context;
    /// a legacy-only head without those records is unavailable in this profile.
    #[inline(never)]
    pub fn export_current_native_live_v1(&self, target_block: BlockIdV0) -> DurableResult<Vec<u8>> {
        (|| -> Result<_> {
            let _guard = self.lock_operation()?;
            reject_sqlite_sidecars_v0(&self.path)?;
            let connection = open_immutable_connection_v0(&self.path)?;
            connection.execute_batch("BEGIN DEFERRED TRANSACTION")?;
            screen_legacy_export_inputs(&connection)?;
            verify_schema_v0(&connection)?;
            ensure!(
                schema_version(&connection)? == LATER_SCHEMA_VERSION,
                "native live requires explicit schema10"
            );
            let metadata = load_metadata_v0(&connection, &self.config)?;
            ensure!(
                metadata.head.block_id().as_bytes() == target_block.as_bytes(),
                "native live target is not current head"
            );
            validate_metadata_v0(&connection, &self.config, &metadata)?;
            let p = load_p(&connection, target_block.as_bytes())?
                .context("native live retained epoch P missing")?;
            ensure!(
                p.status == 1
                    && p.commit_sequence.is_some()
                    && p.target_head()? == metadata.head
                    && p.snapshot == metadata.snapshot
                    && p.snapshot_digest == metadata.snapshot_digest,
                "native live exact committed head P mismatch"
            );
            let header = decode_header(&p.header)?;
            ensure!(
                matches!(
                    header.block_kind(),
                    BlockKind::Regular | BlockKind::EpochCheckpoint | BlockKind::EpochHandoff
                ),
                "native live terminal is not an application block"
            );
            let prefix =
                lineage_resolver::resolve(&connection, &self.config, &decode_lineage(&p.lineage)?)?;
            let active = &prefix
                .entries
                .last()
                .context("native live active prefix missing")?
                .audit
                .activation;
            let set = active.new_validator_set();
            let parameters = active.new_consensus_parameters();
            ensure!(
                p.target_set
                    == set
                        .try_cev0_bytes()
                        .map_err(|e| anyhow::anyhow!("native live set: {e:?}"))?
                    && p.target_parameters == parameters.canonical_bytes(),
                "native live strict target configuration mismatch"
            );
            let store = metadata_store(&connection, &self.config, &metadata)?;
            let live = store.verified_live_values_v0(p.target_height)?;
            let entries = live
                .into_iter()
                .map(|(key, value)| NativeCurrentLiveEntryV1 { key, value })
                .collect();
            let bytes = NativeCurrentLiveExportV1 {
                application_version: p.target_height,
                state_root: *header.state_root().as_bytes(),
                schema_digest: crate::native_current_live_schema_digest_v1(),
                entries,
            }
            .encode()?;
            crate::recompute_native_current_live_v1(&bytes, &header, set, parameters)?;
            connection.execute_batch("ROLLBACK")?;
            ensure!(
                fresh_export_metadata(&self.path, &self.config)? == metadata,
                "native live concurrent metadata change"
            );
            #[cfg(unix)]
            self.confirm_namespace_identity_v1()?;
            Ok(bytes)
        })()
        .map_err(local_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_live_export_sql_screen_enforces_types_count_and_byte_bounds() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch("CREATE TABLE items(id BLOB, payload BLOB, optional_blob BLOB)")
            .unwrap();
        connection
            .execute("INSERT INTO items VALUES(zeroblob(8),zeroblob(8),NULL)", [])
            .unwrap();
        let columns = [
            fixed("id", 8),
            bounded("payload", 8),
            optional("optional_blob", 8),
        ];
        assert_eq!(
            screen_blob_table(&connection, "items", 2, 16, &columns).unwrap(),
            1
        );
        for mutation in [
            "id=zeroblob(9)",
            "id='12345678'",
            "payload=zeroblob(9)",
            "payload=CAST(X'80' AS TEXT)",
            "payload=17",
            "payload=17.5",
            "payload=NULL",
            "optional_blob=zeroblob(9)",
            "optional_blob='12345678'",
        ] {
            connection.execute("SAVEPOINT mutant", []).unwrap();
            connection
                .execute(&format!("UPDATE items SET {mutation}"), [])
                .unwrap();
            assert!(
                screen_blob_table(&connection, "items", 2, 64, &columns).is_err(),
                "{mutation}"
            );
            connection
                .execute_batch("ROLLBACK TO mutant; RELEASE mutant")
                .unwrap();
        }
        connection
            .execute("INSERT INTO items VALUES(zeroblob(8),zeroblob(8),NULL)", [])
            .unwrap();
        assert!(screen_blob_table(&connection, "items", 2, 31, &columns).is_err());
        assert_eq!(
            screen_blob_table(&connection, "items", 2, 32, &columns).unwrap(),
            2
        );
        assert!(screen_blob_table(&connection, "items", 1, 32, &columns).is_err());
    }

    #[test]
    fn native_live_export_fixed_sql_fields_require_exact_blob_width() {
        let connection = Connection::open_in_memory().unwrap();
        let number: u64 = connection
            .query_row(
                "SELECT ?1 AS field",
                [17u64.to_be_bytes().as_slice()],
                |row| col64(row, "field"),
            )
            .unwrap();
        assert_eq!(number, 17);
        let hash: [u8; 32] = connection
            .query_row("SELECT ?1 AS field", [[9u8; 32].as_slice()], |row| {
                col32(row, "field")
            })
            .unwrap();
        assert_eq!(hash, [9; 32]);
        for expression in ["zeroblob(33)", "'not a blob'", "1", "1.5", "NULL"] {
            let query = format!("SELECT {expression} AS field");
            assert!(connection
                .query_row(&query, [], |row| col32(row, "field"))
                .is_err());
            assert!(connection
                .query_row(&query, [], |row| col64(row, "field"))
                .is_err());
            if expression == "NULL" {
                assert_eq!(
                    connection
                        .query_row(&query, [], |row| opt32(row, "field"))
                        .unwrap(),
                    None
                );
                assert_eq!(
                    connection
                        .query_row(&query, [], |row| opt64(row, "field"))
                        .unwrap(),
                    None
                );
            } else {
                assert!(connection
                    .query_row(&query, [], |row| opt32(row, "field"))
                    .is_err());
                assert!(connection
                    .query_row(&query, [], |row| opt64(row, "field"))
                    .is_err());
            }
        }
    }
}
