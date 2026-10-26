//! Bounded retained-record codec and working-partition binding.
//!
//! This is not authentication of unselected accounts or history. The selected
//! load still materializes the real COW graph and runs the complete State and
//! history verifiers. A raw native record's self-digest grants no trust here.
use super::{
    bytes32, canonical, check_authoritative_namespace, check_typed_rows, native_authenticated,
    Snapshot, MAX_BYTES, SCHEMA,
};
use crate::account_archive_execution::state_witness::COMMITMENT_SCHEMA;
use crate::{ensure, Error, Result, Settings};
use rusqlite::{params, Connection};
use trnm_mvcc_fee::pon_executor;
use trnm_protocol::pon_wire::Hash;

/// Decode one bounded row against its actual SQL key and native record. These
/// checks bind local observations; only the original full verifiers authorize
/// a complete State. Never export a trusted commitment/cached-validity value.
pub(super) fn decode(
    db: &Connection,
    settings: &Settings,
    block: Hash,
    bytes: &[u8],
) -> Result<(Snapshot, native_authenticated::Record)> {
    (|| {
        ensure(bytes.len() <= MAX_BYTES, "NATIVE_SHARED_SNAPSHOT_LIMIT")?;
        let snapshot: Snapshot = serde_json::from_slice(bytes)?;
        ensure(
            canonical(&snapshot)?.as_slice() == bytes
                && snapshot.schema == SCHEMA
                && snapshot.block == block
                && block != settings.genesis()
                && snapshot.id == snapshot.digest(settings)?
                && snapshot
                    .working
                    .keys()
                    .all(|key| !key.starts_with("account:")),
            "NATIVE_SHARED_SNAPSHOT_RECORD",
        )?;
        let native = native_authenticated::load(db, block)?;
        ensure(
            snapshot.native_commitment == native.id
                && native.state.schema == COMMITMENT_SCHEMA
                && native.state.network == settings.network()
                && native.state.parameters == settings.parameters()
                && native.state.genesis == settings.genesis()
                && native.state.non_account_count == snapshot.working.len() as u64
                && native.state.non_account_root
                    == pon_executor::root(&snapshot.working).map_err(Error::from)?,
            "NATIVE_SHARED_SNAPSHOT_BINDING",
        )?;
        Ok((snapshot, native))
    })()
    .map_err(Error::local_integrity)
}

/// Stream every retained record, never a Vec of all payloads. The original
/// per-file bound and64 retained rows (65 only during save) do not increase.
/// The final no-caller-callback read phases call this even for optional None.
pub(super) fn check(db: &Connection, settings: &Settings, limit: usize) -> Result<()> {
    (|| {
        check_authoritative_namespace(db)?;
        check_typed_rows(db, limit)?;
        let mut statement = db.prepare(
            "SELECT block,substr(data,1,?1) FROM main.native_io_shared_snapshots LIMIT ?2",
        )?;
        let mut rows = statement.query(params![MAX_BYTES + 1, limit + 1])?;
        let mut count = 0usize;
        while let Some(row) = rows.next()? {
            count += 1;
            ensure(count <= limit, "SNAPSHOT_LIMIT")?;
            let block = bytes32(row.get(0)?)?;
            let bytes: Vec<u8> = row.get(1)?;
            decode(db, settings, block, &bytes)?;
        }
        Ok(())
    })()
    .map_err(Error::local_integrity)
}
