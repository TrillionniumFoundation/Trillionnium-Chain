//! Exact schema12 storage framing. These decoded facts never grant authority.
use super::*;
use crate::poco_preparation_journal::{
    HistoricalReplayPreparationKeyV1, HistoricalReplayPreparationSelectionV1,
};
use rusqlite::types::ValueRef;
use trnm_consensus_types::EpochActivationEvidenceBytesV0;

pub(super) const INSTALLED_SCHEMA_VERSION: u64 = 12;
const MAX_HISTORY: usize = 64 * 1024 * 1024;
const MAX_AGGREGATE: u64 = 2 * 1024 * 1024 * 1024;
const MAX_SELECTION: usize = 64 * 1024;
const ROOT_CAPS: [usize; 8] = [8388608, 4096, 8388608, 1048576, 4096, 1048576, 4096, 4096];

pub(super) const SCHEMA_V1: &[(&str, &str)] = &[
    ("native_historical_replay_base_v1", "CREATE TABLE native_historical_replay_base_v1 (
      singleton INTEGER PRIMARY KEY CHECK(singleton=1),
      revision INTEGER NOT NULL CHECK(revision=1),
      source_schema BLOB NOT NULL CHECK(source_schema=x'000000000000000a'),
      store_id BLOB NOT NULL CHECK(length(store_id)=32),
      signer_policy BLOB NOT NULL CHECK(length(signer_policy)=32),
      source_head BLOB NOT NULL CHECK(length(source_head)=104),
      source_sequence BLOB NOT NULL CHECK(length(source_sequence)=8),
      source_p_digest BLOB NOT NULL CHECK(length(source_p_digest)=32),
      source_p_sequence BLOB NOT NULL CHECK(length(source_p_sequence)=8),
      source_commit_sequence BLOB NOT NULL CHECK(length(source_commit_sequence)=8),
      source_header BLOB NOT NULL CHECK(length(source_header) BETWEEN 1 AND 4096),
      source_snapshot_digest BLOB NOT NULL CHECK(length(source_snapshot_digest)=32),
      source_commands_digest BLOB NOT NULL CHECK(length(source_commands_digest)=32),
      source_nonces_digest BLOB NOT NULL CHECK(length(source_nonces_digest)=32),
      source_active_set BLOB NOT NULL CHECK(length(source_active_set) BETWEEN 1 AND 1048576),
      source_active_parameters BLOB NOT NULL CHECK(length(source_active_parameters) BETWEEN 1 AND 4096),
      source_prefix BLOB NOT NULL CHECK(length(source_prefix) BETWEEN 4 AND 1028),
      source_inventory_digest BLOB NOT NULL CHECK(length(source_inventory_digest)=32),
      source_journal_selection BLOB NOT NULL CHECK(length(source_journal_selection) BETWEEN 16 AND 65536),
      input_digest BLOB NOT NULL CHECK(length(input_digest)=32),
      run_digest BLOB NOT NULL CHECK(length(run_digest)=32),
      input_count BLOB NOT NULL CHECK(length(input_count)=8),
      input_byte_len BLOB NOT NULL CHECK(length(input_byte_len)=8),
      transition_count BLOB NOT NULL CHECK(length(transition_count)=8),
      authority BLOB NOT NULL CHECK(length(authority) BETWEEN 22 AND 67108864),
      authority_digest BLOB NOT NULL CHECK(length(authority_digest)=32),
      target_head BLOB NOT NULL CHECK(length(target_head)=104),
      target_header BLOB NOT NULL CHECK(length(target_header) BETWEEN 1 AND 4096),
      target_set BLOB NOT NULL CHECK(length(target_set) BETWEEN 1 AND 1048576),
      target_parameters BLOB NOT NULL CHECK(length(target_parameters) BETWEEN 1 AND 4096),
      snapshot BLOB NOT NULL CHECK(length(snapshot) BETWEEN 1 AND 268435456),
      snapshot_digest BLOB NOT NULL CHECK(length(snapshot_digest)=32),
      commands BLOB NOT NULL CHECK(length(commands) BETWEEN 4 AND 16777216),
      commands_digest BLOB NOT NULL CHECK(length(commands_digest)=32),
      nonces BLOB NOT NULL CHECK(length(nonces) BETWEEN 4 AND 16777216),
      nonces_digest BLOB NOT NULL CHECK(length(nonces_digest)=32),
      lifecycle BLOB NOT NULL CHECK(length(lifecycle) BETWEEN 1 AND 1048576),
      lifecycle_digest BLOB NOT NULL CHECK(length(lifecycle_digest)=32),
      application_count BLOB NOT NULL CHECK(length(application_count)=8),
      install_sequence BLOB NOT NULL CHECK(length(install_sequence)=8),
      base_digest BLOB NOT NULL CHECK(length(base_digest)=32)
    ) STRICT"),
    ("native_historical_replay_input_v1", "CREATE TABLE native_historical_replay_input_v1 (
      ordinal BLOB PRIMARY KEY NOT NULL CHECK(length(ordinal)=8),
      block_id BLOB NOT NULL UNIQUE CHECK(length(block_id)=32),
      header BLOB NOT NULL CHECK(length(header) BETWEEN 1 AND 4096),
      tag INTEGER NOT NULL CHECK(tag IN (0,1)),
      payload BLOB CHECK(payload IS NULL OR length(payload) BETWEEN 4 AND 4194304),
      record_digest BLOB NOT NULL CHECK(length(record_digest)=32),
      CHECK((tag=0 AND payload IS NOT NULL) OR (tag=1 AND payload IS NULL))
    ) STRICT, WITHOUT ROWID"),
    ("native_replay_execution_p_v1", "CREATE TABLE native_replay_execution_p_v1 (
      block_id BLOB PRIMARY KEY NOT NULL CHECK(length(block_id)=32),
      base_digest BLOB NOT NULL CHECK(length(base_digest)=32),
      p_sequence BLOB NOT NULL UNIQUE CHECK(length(p_sequence)=8),
      status INTEGER NOT NULL CHECK(status IN (0,1)),
      parent_kind INTEGER NOT NULL CHECK(parent_kind IN (0,1)),
      parent_head BLOB NOT NULL CHECK(length(parent_head)=104),
      parent_p_digest BLOB CHECK(parent_p_digest IS NULL OR length(parent_p_digest)=32),
      header BLOB NOT NULL CHECK(length(header) BETWEEN 1 AND 4096),
      artifact BLOB NOT NULL CHECK(length(artifact) BETWEEN 1 AND 16777216),
      artifact_digest BLOB NOT NULL CHECK(length(artifact_digest)=32),
      snapshot BLOB NOT NULL CHECK(length(snapshot) BETWEEN 1 AND 268435456),
      snapshot_digest BLOB NOT NULL CHECK(length(snapshot_digest)=32),
      commands BLOB NOT NULL CHECK(length(commands) BETWEEN 4 AND 16777216),
      commands_digest BLOB NOT NULL CHECK(length(commands_digest)=32),
      nonces BLOB NOT NULL CHECK(length(nonces) BETWEEN 4 AND 16777216),
      nonces_digest BLOB NOT NULL CHECK(length(nonces_digest)=32),
      lifecycle BLOB NOT NULL CHECK(length(lifecycle) BETWEEN 1 AND 1048576),
      lifecycle_digest BLOB NOT NULL CHECK(length(lifecycle_digest)=32),
      p_digest BLOB NOT NULL CHECK(length(p_digest)=32),
      commit_sequence BLOB UNIQUE CHECK(commit_sequence IS NULL OR length(commit_sequence)=8),
      commit_id BLOB CHECK(commit_id IS NULL OR length(commit_id)=32),
      CHECK((parent_kind=0 AND parent_p_digest IS NULL) OR (parent_kind=1 AND parent_p_digest IS NOT NULL)),
      CHECK((status=0 AND commit_sequence IS NULL AND commit_id IS NULL) OR (status=1 AND commit_sequence IS NOT NULL AND commit_id IS NOT NULL))
    ) STRICT, WITHOUT ROWID"),
    ("native_replay_execution_finality_v1", "CREATE TABLE native_replay_execution_finality_v1 (
      block_id BLOB PRIMARY KEY NOT NULL CHECK(length(block_id)=32),
      p_digest BLOB NOT NULL CHECK(length(p_digest)=32),
      commit_sequence BLOB NOT NULL UNIQUE CHECK(length(commit_sequence)=8),
      proof BLOB NOT NULL CHECK(length(proof) BETWEEN 1 AND 8388608),
      proof_digest BLOB NOT NULL CHECK(length(proof_digest)=32),
      record_digest BLOB NOT NULL CHECK(length(record_digest)=32),
      FOREIGN KEY(block_id) REFERENCES native_replay_execution_p_v1(block_id)
    ) STRICT, WITHOUT ROWID"),
];

pub(super) struct StoredHistoricalBaseV1 {
    pub(super) source: SourcePinV1,
    pub(super) history: NativeHistoricalReplayV1,
    pub(super) input_digest: [u8; 32],
    pub(super) run_digest: [u8; 32],
    pub(super) computed: execution::ComputedHistoricalReplayV1,
    pub(super) install_sequence: u64,
    pub(super) base_digest: [u8; 32],
}

pub(super) fn verify_schema_v1(connection: &Connection) -> Result<()> {
    source::screen_source_schema_v1(connection)?;
    ensure!(
        schema_version(connection)? == INSTALLED_SCHEMA_VERSION,
        "historical storage requires physical schema12"
    );
    let mut expected = EXPECTED_SCHEMA_V0
        .iter()
        .chain(SCHEMA)
        .chain(LATER_SCHEMA)
        .chain(SCHEMA_V1)
        .map(|(name, sql)| (name.to_string(), normalize_sql_v0(sql)))
        .collect::<Vec<_>>();
    expected.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut statement = connection.prepare(
        "SELECT type,name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
    )?;
    let mut rows = statement.query([])?;
    let mut actual = Vec::new();
    while let Some(row) = rows.next()? {
        let kind: String = row.get(0)?;
        ensure!(kind == "table", "historical schema unexpected object");
        let name: String = row.get(1)?;
        let sql: String = row.get(2)?;
        actual.push((name, normalize_sql_v0(&sql)));
    }
    ensure!(
        actual == expected,
        "historical schema exact inventory mismatch"
    );
    Ok(())
}

// Fixed-width values are borrowed directly from SQLite; CHECK constraints are
// never assumed to have screened data written with ignore_check_constraints.
fn fixed<const N: usize>(row: &rusqlite::Row<'_>, column: &str) -> Result<[u8; N]> {
    match row.get_ref(column)? {
        ValueRef::Blob(value) => value
            .try_into()
            .map_err(|_| anyhow::anyhow!("historical fixed width: {column}")),
        _ => anyhow::bail!("historical fixed type: {column}"),
    }
}
fn u64_field(row: &rusqlite::Row<'_>, column: &str) -> Result<u64> {
    Ok(u64::from_be_bytes(fixed(row, column)?))
}
fn blob(row: &rusqlite::Row<'_>, column: &str, minimum: usize, maximum: usize) -> Result<Vec<u8>> {
    match row.get_ref(column)? {
        ValueRef::Blob(value) if (minimum..=maximum).contains(&value.len()) => Ok(value.to_vec()),
        _ => anyhow::bail!("historical bounded blob: {column}"),
    }
}
fn decode_head(bytes: [u8; 104]) -> Result<ApplicationHeadV0> {
    Ok(ApplicationHeadV0::new(
        HeightV0::new(u64::from_be_bytes(bytes[..8].try_into()?)),
        BlockIdV0::new(bytes[8..40].try_into()?)?,
        StateRootV0::new(bytes[40..72].try_into()?)?,
        ApplicationCommitIdV0::new(bytes[72..].try_into()?)?,
    ))
}
fn protocol<T, E: core::fmt::Debug>(result: core::result::Result<T, E>) -> Result<T> {
    result.map_err(|error| anyhow::anyhow!("historical storage canonical bytes: {error:?}"))
}

fn columns(connection: &Connection, table: &str) -> Result<Vec<String>> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
    let names = statement
        .query_map([], |row| row.get(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names)
}
fn blob_bounds(table: &str, column: &str) -> (usize, usize, bool) {
    let optional = matches!(column, "parent_p_digest" | "commit_sequence" | "commit_id")
        && table == "native_replay_execution_p_v1"
        || column == "payload";
    let bounds = match column {
        "source_head" | "target_head" | "parent_head" => (104, 104),
        "source_schema"
        | "source_sequence"
        | "source_p_sequence"
        | "source_commit_sequence"
        | "input_count"
        | "input_byte_len"
        | "transition_count"
        | "application_count"
        | "install_sequence"
        | "ordinal"
        | "p_sequence"
        | "commit_sequence" => (8, 8),
        "source_header"
        | "target_header"
        | "header"
        | "source_active_parameters"
        | "target_parameters" => (1, 4096),
        "source_active_set" | "target_set" | "lifecycle" => (1, 1048576),
        "source_prefix" => (4, 1028),
        "source_journal_selection" => (16, MAX_SELECTION),
        "authority" => (22, MAX_HISTORY),
        "snapshot" => (1, 268435456),
        "commands" | "nonces" => (4, 16777216),
        "artifact" => (1, 16777216),
        "payload" => (4, 4194304),
        "proof" => (1, 8388608),
        _ => (32, 32),
    };
    (bounds.0, bounds.1, optional)
}
fn screen_table(connection: &Connection, table: &str, extra: &str) -> Result<(u64, u64)> {
    let names = columns(connection, table)?;
    let mut checks = Vec::new();
    let mut sizes = Vec::new();
    for column in &names {
        let q = format!("\"{column}\"");
        if matches!(
            column.as_str(),
            "singleton" | "revision" | "tag" | "status" | "parent_kind"
        ) {
            checks.push(format!("typeof({q})='integer'"));
        } else {
            let (minimum, maximum, optional) = blob_bounds(table, column);
            let check =
                format!("typeof({q})='blob' AND length({q}) BETWEEN {minimum} AND {maximum}");
            checks.push(if optional {
                format!("({q} IS NULL OR ({check}))")
            } else {
                format!("({check})")
            });
        }
        sizes.push(format!(
            "CASE WHEN typeof({q})='blob' THEN length({q}) ELSE 0 END"
        ));
    }
    checks.push(format!("({extra})"));
    let sql = format!("SELECT COUNT(*),COALESCE(SUM({}),0),COALESCE(SUM(CASE WHEN {} THEN 0 ELSE 1 END),0) FROM \"{table}\"", sizes.join("+"), checks.join(" AND "));
    let (count, bytes, bad): (i64, i64, i64) =
        connection.query_row(&sql, [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    ensure!(
        count >= 0 && bytes >= 0 && bad == 0,
        "historical storage SQL type/length/value screen: {table}"
    );
    ensure!(
        bytes as u64 <= MAX_AGGREGATE,
        "historical storage table byte bound"
    );
    Ok((count as u64, bytes as u64))
}

pub(super) fn screen_inputs_v1(connection: &Connection) -> Result<()> {
    verify_schema_v1(connection)?;
    source::screen_source_inventory_v1(connection)?;
    let mut total = 0u64;
    for (name, _) in EXPECTED_SCHEMA_V0.iter().chain(SCHEMA).chain(LATER_SCHEMA) {
        let sums = columns(connection, name)?.iter().map(|column| format!("CASE WHEN typeof(\"{column}\")='blob' THEN length(\"{column}\") WHEN typeof(\"{column}\")='text' THEN length(CAST(\"{column}\" AS BLOB)) ELSE 0 END")).collect::<Vec<_>>();
        let bytes: i64 = connection.query_row(
            &format!("SELECT COALESCE(SUM({}),0) FROM \"{name}\"", sums.join("+")),
            [],
            |row| row.get(0),
        )?;
        ensure!(bytes >= 0, "historical source byte sum overflow");
        total = total
            .checked_add(bytes as u64)
            .context("historical source size overflow")?;
    }
    let legacy_p_count: i64 = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM native_durable_execution_p_v0)
              + (SELECT COUNT(*) FROM native_durable_execution_p_v1)",
        [],
        |row| row.get(0),
    )?;
    let replay_p_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM native_replay_execution_p_v1",
        [],
        |row| row.get(0),
    )?;
    ensure!(
        legacy_p_count >= 0
            && replay_p_count >= 0
            && (legacy_p_count as u64).saturating_add(replay_p_count as u64) <= 128,
        "historical combined P row bound"
    );
    for (index, (table, _)) in SCHEMA_V1.iter().enumerate() {
        let extra = match index {
            0 => "singleton=1 AND revision=1 AND source_schema=x'000000000000000a'",
            1 => "(tag=0 AND payload IS NOT NULL) OR (tag=1 AND payload IS NULL)",
            2 => "status IN (0,1) AND ((parent_kind=0 AND parent_p_digest IS NULL) OR (parent_kind=1 AND parent_p_digest IS NOT NULL)) AND ((status=0 AND commit_sequence IS NULL AND commit_id IS NULL) OR (status=1 AND commit_sequence IS NOT NULL AND commit_id IS NOT NULL))",
            _ => "1",
        };
        let (count, bytes) = screen_table(connection, table, extra)?;
        ensure!(
            match index {
                0 => count == 1,
                1 => (1..=256).contains(&count),
                2 => count <= 128,
                3 => {
                    let p_count: u64 = connection.query_row(
                        "SELECT COUNT(*) FROM native_replay_execution_p_v1",
                        [],
                        |row| row.get(0),
                    )?;
                    let pending: i64 = connection.query_row(
                        "SELECT COUNT(*) FROM native_replay_execution_p_v1 WHERE status=0",
                        [],
                        |row| row.get(0),
                    )?;
                    let proof_bytes: i64 = connection.query_row(
                        "SELECT COALESCE(SUM(CASE WHEN typeof(proof)='blob' THEN length(proof) ELSE 0 END),0) FROM native_replay_execution_finality_v1",
                        [],
                        |row| row.get(0),
                    )?;
                    (0..=8).contains(&pending)
                        && (0..=64 * 1024 * 1024).contains(&proof_bytes)
                        && count <= p_count
                }
                _ => false,
            },
            "historical storage row count/profile: {table}"
        );
        total = total
            .checked_add(bytes)
            .context("historical aggregate overflow")?;
        ensure!(
            total <= MAX_AGGREGATE,
            "historical storage aggregate byte bound"
        );
    }
    let canonical_size: i64 = connection.query_row(
        "SELECT length(authority)+4+(SELECT COALESCE(SUM(5+length(header)+CASE WHEN tag=0 THEN 4+length(payload) ELSE 0 END),0) FROM native_historical_replay_input_v1) FROM native_historical_replay_base_v1 WHERE singleton=1",
        [], |row| row.get(0),
    )?;
    ensure!(
        (1..=MAX_HISTORY as i64).contains(&canonical_size),
        "historical canonical input byte bound"
    );
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .context("historical framing overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("historical truncated framing")?;
        self.offset = end;
        Ok(value)
    }
    fn count(&mut self, cap: usize) -> Result<usize> {
        let count = u32::from_be_bytes(self.take(4)?.try_into()?) as usize;
        ensure!(count <= cap, "historical list count bound");
        Ok(count)
    }
    fn frame(&mut self, minimum: usize, maximum: usize) -> Result<Vec<u8>> {
        let length = self.count(maximum)?;
        ensure!(length >= minimum, "historical short frame");
        Ok(self.take(length)?.to_vec())
    }
    fn finish(&self) -> Result<()> {
        ensure!(self.offset == self.bytes.len(), "historical trailing bytes");
        Ok(())
    }
}
fn push_frame(out: &mut Vec<u8>, bytes: &[u8], minimum: usize, maximum: usize) -> Result<()> {
    ensure!(
        (minimum..=maximum).contains(&bytes.len()),
        "historical frame bound"
    );
    ensure!(
        out.len()
            .checked_add(4)
            .and_then(|n| n.checked_add(bytes.len()))
            .is_some_and(|n| n <= MAX_HISTORY),
        "historical frame aggregate bound"
    );
    out.extend_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn evidence_parts(e: &EpochActivationEvidenceBytesV0) -> [&[u8]; 8] {
    [
        &e.old_checkpoint_finality,
        &e.next_epoch_commitment,
        &e.authorization_kernel,
        &e.old_validator_set,
        &e.old_consensus_parameters,
        &e.new_validator_set,
        &e.new_consensus_parameters,
        &e.authenticated_checkpoint_parent_header,
    ]
}
fn encode_authority(history: &NativeHistoricalReplayV1) -> Result<Vec<u8>> {
    ensure!(
        history.activations.len() <= 32,
        "historical activation count bound"
    );
    let mut out = b"NHA1\0\x01\0\0".to_vec();
    push_frame(&mut out, &history.anchor_header_cev0, 1, 4096)?;
    push_frame(&mut out, &history.terminal_finality_cev0, 1, 8388608)?;
    out.extend_from_slice(&(history.activations.len() as u32).to_be_bytes());
    for evidence in &history.activations {
        for (bytes, cap) in evidence_parts(evidence).into_iter().zip(ROOT_CAPS) {
            push_frame(&mut out, bytes, 1, cap)?;
        }
    }
    Ok(out)
}
fn decode_authority(bytes: &[u8]) -> Result<NativeHistoricalReplayV1> {
    ensure!(
        bytes.len() <= MAX_HISTORY,
        "historical authority byte bound"
    );
    let mut reader = Reader { bytes, offset: 0 };
    ensure!(
        reader.take(8)? == b"NHA1\0\x01\0\0",
        "historical authority revision"
    );
    let anchor_header_cev0 = reader.frame(1, 4096)?;
    let terminal_finality_cev0 = reader.frame(1, 8388608)?;
    let count = reader.count(32)?;
    let mut activations = Vec::with_capacity(count);
    for _ in 0..count {
        let mut parts = Vec::with_capacity(8);
        for cap in ROOT_CAPS {
            parts.push(reader.frame(1, cap)?);
        }
        let [old_checkpoint_finality, next_epoch_commitment, authorization_kernel, old_validator_set, old_consensus_parameters, new_validator_set, new_consensus_parameters, authenticated_checkpoint_parent_header]: [Vec<u8>; 8] = parts.try_into().map_err(|_| anyhow::anyhow!("historical authority root arity"))?;
        activations.push(EpochActivationEvidenceBytesV0 {
            old_checkpoint_finality,
            next_epoch_commitment,
            authorization_kernel,
            old_validator_set,
            old_consensus_parameters,
            new_validator_set,
            new_consensus_parameters,
            authenticated_checkpoint_parent_header,
        });
    }
    reader.finish()?;
    let history = NativeHistoricalReplayV1 {
        anchor_header_cev0,
        terminal_finality_cev0,
        records: Vec::new(),
        activations,
    };
    ensure!(
        encode_authority(&history)? == bytes,
        "historical authority noncanonical framing"
    );
    Ok(history)
}
fn encode_selection(selection: &HistoricalReplayPreparationSelectionV1) -> Result<Vec<u8>> {
    ensure!(
        selection.transition_keys.len() <= 64 && selection.preparation_keys.len() <= 1024,
        "historical journal key count"
    );
    ensure!(
        selection.transition_keys.windows(2).all(|p| p[0] < p[1])
            && selection.preparation_keys.windows(2).all(|p| p[0] < p[1]),
        "historical journal key order"
    );
    let mut out = b"NHJ1\0\x01\0\0".to_vec();
    out.extend_from_slice(&(selection.transition_keys.len() as u32).to_be_bytes());
    for key in &selection.transition_keys {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(&(selection.preparation_keys.len() as u32).to_be_bytes());
    for key in &selection.preparation_keys {
        ensure!(
            key.block_kind == 1
                && selection
                    .transition_keys
                    .binary_search(&key.transition_key)
                    .is_ok(),
            "historical journal key transition"
        );
        out.extend_from_slice(&key.transition_key);
        out.extend_from_slice(&key.block_kind.to_be_bytes());
        out.extend_from_slice(&key.height.to_be_bytes());
        out.extend_from_slice(&key.view.to_be_bytes());
    }
    ensure!(
        out.len() <= MAX_SELECTION,
        "historical journal key byte bound"
    );
    Ok(out)
}
fn decode_selection(bytes: &[u8]) -> Result<HistoricalReplayPreparationSelectionV1> {
    ensure!(
        bytes.len() <= MAX_SELECTION,
        "historical journal selection byte bound"
    );
    let mut reader = Reader { bytes, offset: 0 };
    ensure!(
        reader.take(8)? == b"NHJ1\0\x01\0\0",
        "historical journal selection revision"
    );
    let count = reader.count(64)?;
    let mut transition_keys = Vec::with_capacity(count);
    for _ in 0..count {
        transition_keys.push(reader.take(32)?.try_into()?);
    }
    let count = reader.count(1024)?;
    let mut preparation_keys = Vec::with_capacity(count);
    for _ in 0..count {
        preparation_keys.push(HistoricalReplayPreparationKeyV1 {
            transition_key: reader.take(32)?.try_into()?,
            block_kind: i64::from_be_bytes(reader.take(8)?.try_into()?),
            height: u64::from_be_bytes(reader.take(8)?.try_into()?),
            view: u64::from_be_bytes(reader.take(8)?.try_into()?),
        });
    }
    reader.finish()?;
    let selection = HistoricalReplayPreparationSelectionV1 {
        transition_keys,
        preparation_keys,
    };
    ensure!(
        encode_selection(&selection)? == bytes,
        "historical journal selection canonical framing"
    );
    Ok(selection)
}
fn record_digest(input: &[u8; 32], ordinal: u64, record: &NativeHistoricalRecordV1) -> [u8; 32] {
    let (tag, payload) = match record {
        NativeHistoricalRecordV1::Application {
            application_payload_cev0,
            ..
        } => (0u8, application_payload_cev0.as_slice()),
        NativeHistoricalRecordV1::Seal { .. } => (1u8, &[][..]),
    };
    hash_domain(
        "trnm.native.historical-replay-record.v1",
        &[
            input,
            &ordinal.to_be_bytes(),
            record.header_cev0(),
            &[tag],
            payload,
        ],
    )
}

pub(super) fn insert_base_and_input_v1(
    connection: &Connection,
    prepared: &PreparedNativeReplayBaseV1,
    install_sequence: u64,
    base_digest: [u8; 32],
) -> Result<()> {
    ensure!(
        prepared.source.sequence.checked_add(1) == Some(install_sequence),
        "historical install sequence"
    );
    for (table, _) in SCHEMA_V1 {
        let count: i64 =
            connection.query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |row| {
                row.get(0)
            })?;
        ensure!(count == 0, "historical insertion requires empty new tables");
    }
    let history = NativeHistoricalReplayV1::decode_v1(&prepared.history_bytes)?;
    ensure!(
        history.anchor_header_cev0 == prepared.source.header,
        "historical stored source header mismatch"
    );
    ensure!(
        hash_domain(
            "trnm.native.historical-replay-input.v1",
            &[&prepared.history_bytes]
        ) == prepared.input_digest,
        "historical prepared input digest"
    );
    let authority = encode_authority(&history)?;
    let selection = encode_selection(&prepared.source.journal_selection)?;
    let target_header = protocol(prepared.computed.target_header.try_cev0_bytes())?;
    let target_set = protocol(prepared.computed.target_set.try_cev0_bytes())?;
    let target_parameters = prepared.computed.target_parameters.canonical_bytes();
    let application_count = history
        .records
        .iter()
        .filter(|r| matches!(r, NativeHistoricalRecordV1::Application { .. }))
        .count();
    ensure!(
        application_count == prepared.computed.application_count && application_count > 0,
        "historical prepared application count"
    );
    ensure!(
        history
            .records
            .last()
            .is_some_and(|r| r.header_cev0() == target_header),
        "historical prepared terminal header"
    );
    let source = &prepared.source;
    let computed = &prepared.computed;
    for (bytes, minimum, maximum) in [
        (source.header.as_slice(), 1, 4096),
        (source.active_set.as_slice(), 1, 1048576),
        (source.active_parameters.as_slice(), 1, 4096),
        (source.prefix.as_slice(), 4, 1028),
        (target_set.as_slice(), 1, 1048576),
        (target_parameters.as_slice(), 1, 4096),
        (computed.snapshot.as_slice(), 1, 268435456),
        (computed.commands.as_slice(), 4, 16777216),
        (computed.nonces.as_slice(), 4, 16777216),
        (computed.lifecycle.as_slice(), 1, 1048576),
    ] {
        ensure!(
            (minimum..=maximum).contains(&bytes.len()),
            "historical prepared field bound"
        );
    }
    connection.execute(
        "INSERT INTO native_historical_replay_base_v1 (
          singleton,revision,source_schema,store_id,signer_policy,source_head,source_sequence,
          source_p_digest,source_p_sequence,source_commit_sequence,source_header,
          source_snapshot_digest,source_commands_digest,source_nonces_digest,
          source_active_set,source_active_parameters,source_prefix,source_inventory_digest,
          source_journal_selection,input_digest,run_digest,input_count,input_byte_len,
          transition_count,authority,authority_digest,target_head,target_header,target_set,
          target_parameters,snapshot,snapshot_digest,commands,commands_digest,nonces,nonces_digest,
          lifecycle,lifecycle_digest,application_count,install_sequence,base_digest
        ) VALUES (
          1,1,:schema,:store,:signer,:source_head,:source_sequence,:source_p_digest,
          :source_p_sequence,:source_commit_sequence,:source_header,:source_snapshot_digest,
          :source_commands_digest,:source_nonces_digest,:source_set,:source_parameters,
          :source_prefix,:source_inventory,:selection,:input_digest,:run_digest,:input_count,
          :input_len,:transitions,:authority,:authority_digest,:target_head,:target_header,
          :target_set,:target_parameters,:snapshot,:snapshot_digest,:commands,:commands_digest,
          :nonces,:nonces_digest,:lifecycle,:lifecycle_digest,:applications,:install_sequence,:base_digest
        )",
        rusqlite::named_params! {
            ":schema": 10_u64.to_be_bytes().as_slice(),
            ":store": source.store_id.as_slice(), ":signer": source.signer_policy.as_slice(),
            ":source_head": head_bytes(&source.head).as_slice(),
            ":source_sequence": source.sequence.to_be_bytes().as_slice(),
            ":source_p_digest": source.p_digest.as_slice(),
            ":source_p_sequence": source.p_sequence.to_be_bytes().as_slice(),
            ":source_commit_sequence": source.commit_sequence.to_be_bytes().as_slice(),
            ":source_header": &source.header, ":source_snapshot_digest": source.snapshot_digest.as_slice(),
            ":source_commands_digest": source.commands_digest.as_slice(), ":source_nonces_digest": source.nonces_digest.as_slice(),
            ":source_set": &source.active_set, ":source_parameters": &source.active_parameters,
            ":source_prefix": &source.prefix, ":source_inventory": source.inventory_digest.as_slice(),
            ":selection": &selection, ":input_digest": prepared.input_digest.as_slice(),
            ":run_digest": prepared.run_digest.as_slice(),
            ":input_count": (history.records.len() as u64).to_be_bytes().as_slice(),
            ":input_len": (prepared.history_bytes.len() as u64).to_be_bytes().as_slice(),
            ":transitions": (history.activations.len() as u64).to_be_bytes().as_slice(),
            ":authority": &authority, ":authority_digest": sha256_v0(&authority).as_slice(),
            ":target_head": head_bytes(&computed.target_head).as_slice(), ":target_header": &target_header,
            ":target_set": &target_set, ":target_parameters": &target_parameters,
            ":snapshot": &computed.snapshot, ":snapshot_digest": sha256_v0(&computed.snapshot).as_slice(),
            ":commands": &computed.commands, ":commands_digest": sha256_v0(&computed.commands).as_slice(),
            ":nonces": &computed.nonces, ":nonces_digest": sha256_v0(&computed.nonces).as_slice(),
            ":lifecycle": &computed.lifecycle, ":lifecycle_digest": sha256_v0(&computed.lifecycle).as_slice(),
            ":applications": (application_count as u64).to_be_bytes().as_slice(),
            ":install_sequence": install_sequence.to_be_bytes().as_slice(), ":base_digest": base_digest.as_slice(),
        },
    )?;
    for (ordinal, record) in history.records.iter().enumerate() {
        let header = decode_header(record.header_cev0())?;
        let (tag, payload): (i64, Option<&[u8]>) = match record {
            NativeHistoricalRecordV1::Application {
                application_payload_cev0,
                ..
            } => (0, Some(application_payload_cev0)),
            NativeHistoricalRecordV1::Seal { .. } => (1, None),
        };
        connection.execute(
            "INSERT INTO native_historical_replay_input_v1(ordinal,block_id,header,tag,payload,record_digest) VALUES(?1,?2,?3,?4,?5,?6)",
            params![(ordinal as u64).to_be_bytes().as_slice(),header.id().as_bytes().as_slice(),record.header_cev0(),tag,payload,record_digest(&prepared.input_digest,ordinal as u64,record).as_slice()],
        )?;
    }
    Ok(())
}

pub(super) fn read_base_and_input_v1(connection: &Connection) -> Result<StoredHistoricalBaseV1> {
    screen_inputs_v1(connection)?;
    let mut statement =
        connection.prepare("SELECT * FROM native_historical_replay_base_v1 WHERE singleton=1")?;
    let mut rows = statement.query([])?;
    let row = rows.next()?.context("historical base missing")?;
    let input_count = u64_field(row, "input_count")?;
    let input_byte_len = u64_field(row, "input_byte_len")?;
    let transition_count = u64_field(row, "transition_count")?;
    let application_count = u64_field(row, "application_count")?;
    ensure!(
        (1..=256).contains(&input_count)
            && transition_count <= 32
            && application_count > 0
            && application_count <= input_count
            && input_byte_len <= MAX_HISTORY as u64,
        "historical stored count bounds"
    );
    let source = SourcePinV1 {
        store_id: fixed(row, "store_id")?,
        signer_policy: fixed(row, "signer_policy")?,
        head: decode_head(fixed(row, "source_head")?)?,
        sequence: u64_field(row, "source_sequence")?,
        p_digest: fixed(row, "source_p_digest")?,
        p_sequence: u64_field(row, "source_p_sequence")?,
        commit_sequence: u64_field(row, "source_commit_sequence")?,
        header: blob(row, "source_header", 1, 4096)?,
        snapshot_digest: fixed(row, "source_snapshot_digest")?,
        commands_digest: fixed(row, "source_commands_digest")?,
        nonces_digest: fixed(row, "source_nonces_digest")?,
        active_set: blob(row, "source_active_set", 1, 1048576)?,
        active_parameters: blob(row, "source_active_parameters", 1, 4096)?,
        prefix: blob(row, "source_prefix", 4, 1028)?,
        inventory_digest: fixed(row, "source_inventory_digest")?,
        journal_selection: decode_selection(&blob(
            row,
            "source_journal_selection",
            16,
            MAX_SELECTION,
        )?)?,
    };
    let input_digest = fixed(row, "input_digest")?;
    let run_digest = fixed(row, "run_digest")?;
    let authority = blob(row, "authority", 22, MAX_HISTORY)?;
    ensure!(
        sha256_v0(&authority) == fixed::<32>(row, "authority_digest")?,
        "historical authority digest"
    );
    let mut history = decode_authority(&authority)?;
    ensure!(
        history.anchor_header_cev0 == source.header
            && history.activations.len() as u64 == transition_count,
        "historical source/authority join"
    );
    let target_header_bytes = blob(row, "target_header", 1, 4096)?;
    let target_header = decode_header(&target_header_bytes)?;
    let target_head = decode_head(fixed(row, "target_head")?)?;
    ensure!(
        target_head.height().get() == target_header.height().get()
            && target_head.block_id().as_bytes() == target_header.id().as_bytes()
            && target_head.state_root().as_bytes() == target_header.state_root().as_bytes(),
        "historical target head/header join"
    );
    let target_set = protocol(trnm_consensus_types::decode_validator_set_v0_exact(&blob(
        row,
        "target_set",
        1,
        1048576,
    )?))?;
    let target_parameters = protocol(trnm_consensus_types::decode_consensus_parameters_v0_exact(
        &blob(row, "target_parameters", 1, 4096)?,
    ))?;
    ensure!(
        target_header.validator_set_id() == target_set.id()
            && target_header.consensus_parameters_hash() == target_parameters.hash(),
        "historical target configuration join"
    );
    let snapshot = blob(row, "snapshot", 1, 268435456)?;
    let commands = blob(row, "commands", 4, 16777216)?;
    let nonces = blob(row, "nonces", 4, 16777216)?;
    let lifecycle = blob(row, "lifecycle", 1, 1048576)?;
    for (bytes, digest_column) in [
        (&snapshot, "snapshot_digest"),
        (&commands, "commands_digest"),
        (&nonces, "nonces_digest"),
        (&lifecycle, "lifecycle_digest"),
    ] {
        ensure!(
            sha256_v0(bytes) == fixed::<32>(row, digest_column)?,
            "historical component digest: {digest_column}"
        );
    }
    let install_sequence = u64_field(row, "install_sequence")?;
    let base_digest = fixed(row, "base_digest")?;
    ensure!(
        source.sequence.checked_add(1) == Some(install_sequence),
        "historical installation sequence mismatch"
    );
    let mut inputs =
        connection.prepare("SELECT * FROM native_historical_replay_input_v1 ORDER BY ordinal")?;
    let mut input_rows = inputs.query([])?;
    while let Some(row) = input_rows.next()? {
        let ordinal = u64_field(row, "ordinal")?;
        ensure!(
            ordinal == history.records.len() as u64 && ordinal < input_count,
            "historical input ordinals"
        );
        let header_cev0 = blob(row, "header", 1, 4096)?;
        let header = decode_header(&header_cev0)?;
        ensure!(
            header.id().as_bytes() == &fixed::<32>(row, "block_id")?,
            "historical input block/header join"
        );
        let tag: i64 = row.get("tag")?;
        let seal = matches!(
            header.block_kind(),
            BlockKind::EpochSeal1 | BlockKind::EpochSeal2
        );
        let record = match tag {
            0 => {
                ensure!(!seal, "historical application row carries seal");
                NativeHistoricalRecordV1::Application {
                    header_cev0,
                    application_payload_cev0: blob(row, "payload", 4, 4194304)?,
                }
            }
            1 => {
                ensure!(
                    seal && matches!(row.get_ref("payload")?, ValueRef::Null),
                    "historical seal row body/tag"
                );
                NativeHistoricalRecordV1::Seal { header_cev0 }
            }
            _ => anyhow::bail!("historical input tag"),
        };
        ensure!(
            record_digest(&input_digest, ordinal, &record) == fixed::<32>(row, "record_digest")?,
            "historical input record digest"
        );
        history.records.push(record);
    }
    ensure!(
        history.records.len() as u64 == input_count
            && history
                .records
                .iter()
                .filter(|r| matches!(r, NativeHistoricalRecordV1::Application { .. }))
                .count() as u64
                == application_count,
        "historical input complete count"
    );
    ensure!(
        history
            .records
            .last()
            .is_some_and(|record| record.header_cev0() == target_header_bytes),
        "historical input terminal header"
    );
    let canonical = history.encode_v1()?;
    ensure!(
        canonical.len() as u64 == input_byte_len
            && hash_domain("trnm.native.historical-replay-input.v1", &[&canonical]) == input_digest,
        "historical reconstructed input digest"
    );
    Ok(StoredHistoricalBaseV1 {
        source,
        history,
        input_digest,
        run_digest,
        computed: execution::ComputedHistoricalReplayV1 {
            target_head,
            target_header,
            target_set,
            target_parameters,
            snapshot,
            commands,
            nonces,
            lifecycle,
            application_count: usize::try_from(application_count)?,
        },
        install_sequence,
        base_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_storage_authority_framing_rejects_unbounded_or_trailing_roots() {
        let history = NativeHistoricalReplayV1 {
            anchor_header_cev0: vec![1],
            terminal_finality_cev0: vec![2],
            records: Vec::new(),
            activations: vec![EpochActivationEvidenceBytesV0 {
                old_checkpoint_finality: vec![3],
                next_epoch_commitment: vec![4],
                authorization_kernel: vec![5],
                old_validator_set: vec![6],
                old_consensus_parameters: vec![7],
                new_validator_set: vec![8],
                new_consensus_parameters: vec![9],
                authenticated_checkpoint_parent_header: vec![10],
            }],
        };
        let bytes = encode_authority(&history).unwrap();
        assert_eq!(decode_authority(&bytes).unwrap(), history);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_authority(&trailing).is_err());
        assert!(decode_authority(&bytes[..bytes.len() - 1]).is_err());
        let mut count = bytes.clone();
        count[18..22].copy_from_slice(&33_u32.to_be_bytes());
        assert!(decode_authority(&count).is_err());
        let mut width = bytes;
        width[8..12].copy_from_slice(&4097_u32.to_be_bytes());
        assert!(decode_authority(&width).is_err());
    }

    #[test]
    fn historical_storage_journal_selection_is_exact_and_ordered() {
        let mut selection = HistoricalReplayPreparationSelectionV1 {
            transition_keys: vec![[1; 32]],
            preparation_keys: vec![HistoricalReplayPreparationKeyV1 {
                transition_key: [1; 32],
                block_kind: 1,
                height: 8,
                view: 12,
            }],
        };
        let bytes = encode_selection(&selection).unwrap();
        assert_eq!(decode_selection(&bytes).unwrap(), selection);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_selection(&trailing).is_err());
        let mut count = bytes;
        count[8..12].copy_from_slice(&65_u32.to_be_bytes());
        assert!(decode_selection(&count).is_err());
        selection.preparation_keys[0].transition_key = [2; 32];
        assert!(encode_selection(&selection).is_err());
        selection.preparation_keys[0].transition_key = [1; 32];
        selection.transition_keys.push([1; 32]);
        assert!(encode_selection(&selection).is_err());
    }

    #[test]
    fn historical_storage_sql_screen_rejects_bypassed_width_and_tag_checks() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA_V1[1].1).unwrap();
        connection.execute(
            "INSERT INTO native_historical_replay_input_v1 VALUES(zeroblob(8),zeroblob(32),x'01',0,zeroblob(4),zeroblob(32))",
            [],
        ).unwrap();
        let screen = || {
            screen_table(
                &connection,
                SCHEMA_V1[1].0,
                "(tag=0 AND payload IS NOT NULL) OR (tag=1 AND payload IS NULL)",
            )
        };
        assert_eq!(screen().unwrap().0, 1);
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        connection
            .execute(
                "UPDATE native_historical_replay_input_v1 SET block_id=zeroblob(33)",
                [],
            )
            .unwrap();
        assert!(screen().is_err());
        connection
            .execute(
                "UPDATE native_historical_replay_input_v1 SET block_id=zeroblob(32),tag=1",
                [],
            )
            .unwrap();
        assert!(screen().is_err());
        connection
            .execute(
                "UPDATE native_historical_replay_input_v1 SET payload=NULL",
                [],
            )
            .unwrap();
        assert!(screen().is_ok());
    }
}
