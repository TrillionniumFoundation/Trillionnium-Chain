//! Read-only CMH2 export from one actual native SQLite snapshot.
//!
//! Retained packet/header identities and complete States are re-read; the
//! existing state owner checks its roots and deltas. This is not a new W1 or
//! transaction replay, source-finality proof, anti-rollback witness, or cutover.
//! CMH2 includes Header/trace and full States/configuration; packet transaction
//! and proof bodies are read for the existing packet check but not migrated.
//! Source dimensions are admitted before complete State materialization. This
//! does not charge those SQL/owner reads to ContentReadBudget, bound process
//! RSS/SQLite pages or preempt an individual SQL, JSON or root calculation.

use super::{Node, StateBackend};
use crate::{ensure, Error, Result};
use rusqlite::{params, Row};
use std::time::{Duration, Instant};
use trnm_mvcc_fee::{
    content_commitment_v1::{
        migration_history_snapshot_size_v2, observe_migration_history_with_progress_v2,
        verify_migration_history_with_progress_v2, MigrationHistoryBlockV2,
        MigrationHistoryReadbackV2, MigrationHistorySourceV2, SnapshotContentErrorV1,
        MAX_MIGRATION_HISTORY_BLOCKS_V2, MAX_MIGRATION_HISTORY_BYTES_V2, MAX_SNAPSHOT_KEY_BYTES_V1,
        MAX_SNAPSHOT_ROWS_V1, MAX_SNAPSHOT_VALUE_BYTES_V1,
    },
    pon_executor::pq_accounts_v2::migration_inventory_v1::SourcePins,
};
use trnm_protocol::content_commitment::{
    ContentClaimV1, ContentContextV1, ContentReadBudget, ObservedContentV1,
};
use trnm_protocol::pon_wire::Hash;

/// Cooperative, not preemptive: the existing bounded individual SQL/root
/// operations may finish before observing the next deadline check.
pub const MAX_MIGRATION_HISTORY_DURATION_V2: Duration = Duration::from_secs(30);
/// Aggregate admitted snapshot, delta and selected-active-KV source bytes.
/// This is distinct from the final 32 MiB CMH2 content/read budget. Decoding
/// allocations, SQLite pages, owner indexes and repeated replay reads differ.
pub const MAX_MIGRATION_HISTORY_SOURCE_BYTES_V2: u64 = 4 * MAX_MIGRATION_HISTORY_BYTES_V2;
const MAX_SOURCE_DELTA_ROWS: usize = 2 * MAX_SNAPSHOT_ROWS_V1;

#[derive(Default)]
struct SourceAdmission {
    bytes: u64,
}

impl SourceAdmission {
    fn charge(&mut self, bytes: u64) -> Result<()> {
        self.bytes = self.bytes.checked_add(bytes).ok_or("CMH2_SOURCE_BYTES")?;
        ensure(
            self.bytes <= MAX_MIGRATION_HISTORY_SOURCE_BYTES_V2,
            "CMH2_SOURCE_BYTES",
        )
    }
}

fn dimension(row: &Row<'_>, index: usize, kind: &str, nullable: bool, maximum: u64) -> Result<u64> {
    let actual: String = row.get(index)?;
    let length: Option<i64> = row.get(index + 1)?;
    if nullable && actual == "null" {
        ensure(length.is_none(), "CMH2_SOURCE_DIMENSIONS")?;
        return Ok(0);
    }
    ensure(actual == kind, "CMH2_SOURCE_DIMENSIONS")?;
    let length = length
        .and_then(|value| u64::try_from(value).ok())
        .ok_or("CMH2_SOURCE_DIMENSIONS")?;
    ensure(length <= maximum, "CMH2_SOURCE_DIMENSIONS")?;
    Ok(length)
}

fn live(deadline: Instant) -> Result<()> {
    ensure(Instant::now() < deadline, "CMH2_DEADLINE")
}

fn content_error(error: SnapshotContentErrorV1) -> Error {
    Error::from(format!("CMH2_CONTENT:{error}"))
}

fn reserve_state(total: &mut u64, bytes: u64) -> Result<()> {
    // A conservative 512-byte charge per snapshot covers both CMH2 and HST2
    // framing. Actual CMH2 encoding separately enforces its exact byte limit.
    *total = total
        .checked_add(bytes)
        .and_then(|value| value.checked_add(512))
        .ok_or("CMH2_RETAINED_BYTES")?;
    ensure(
        *total <= MAX_MIGRATION_HISTORY_BYTES_V2,
        "CMH2_RETAINED_BYTES",
    )
}

impl Node {
    // All selected ancestry is checked before any complete historical State is
    // materialized. These bounded dimension queries never copy source blobs.
    // They are conservative admission, not a replacement for the old owner's
    // actual byte, canonical grammar, root, history and continuity checks.
    fn preflight_migration_state_inputs_v2(
        &self,
        id: Hash,
        admitted: &mut SourceAdmission,
        deadline: Instant,
    ) -> Result<()> {
        live(deadline)?;
        {
            let mut statement = self.db.prepare_cached(
                "SELECT typeof(state),length(CAST(state AS BLOB))
                 FROM snapshots WHERE block=? LIMIT 2",
            )?;
            let mut rows = statement.query([id.as_slice()])?;
            if let Some(row) = rows.next()? {
                let kind: String = row.get(0)?;
                let length: Option<i64> = row.get(1)?;
                ensure(
                    kind == "blob"
                        && length.is_some_and(|length| {
                            (0..=MAX_MIGRATION_HISTORY_BYTES_V2 as i64).contains(&length)
                        }),
                    "CMH2_SOURCE_SNAPSHOT",
                )?;
                admitted.charge(length.expect("checked source length") as u64)?;
                ensure(rows.next()?.is_none(), "CMH2_SOURCE_SNAPSHOT")?;
            }
        }
        let mut statement = self.db.prepare_cached(
            "SELECT typeof(key),length(CAST(key AS BLOB)),
             typeof(before),length(CAST(before AS BLOB)),
             typeof(after),length(CAST(after AS BLOB))
             FROM deltas WHERE block=?1 ORDER BY key LIMIT ?2",
        )?;
        let mut rows = statement.query(params![id.as_slice(), MAX_SOURCE_DELTA_ROWS + 1])?;
        let mut count = 0;
        while let Some(row) = rows.next()? {
            count += 1;
            ensure(count <= MAX_SOURCE_DELTA_ROWS, "CMH2_SOURCE_DELTA_ROWS")?;
            if count % 256 == 1 {
                live(deadline)?;
            }
            let bytes = dimension(row, 0, "text", false, MAX_SNAPSHOT_KEY_BYTES_V1 as u64)?
                + dimension(row, 2, "blob", true, MAX_SNAPSHOT_VALUE_BYTES_V1 as u64)?
                + dimension(row, 4, "blob", true, MAX_SNAPSHOT_VALUE_BYTES_V1 as u64)?;
            admitted.charge(bytes)?;
        }
        live(deadline)
    }

    fn preflight_migration_active_inputs_v2(
        &self,
        admitted: &mut SourceAdmission,
        deadline: Instant,
    ) -> Result<()> {
        live(deadline)?;
        let mut statement = self.db.prepare_cached(
            "SELECT typeof(key),length(CAST(key AS BLOB)),
             typeof(value),length(CAST(value AS BLOB))
             FROM kv WHERE slot=?1 ORDER BY key LIMIT ?2",
        )?;
        let mut rows = statement.query(params![self.slot()?, MAX_SNAPSHOT_ROWS_V1 + 1])?;
        let mut count = 0;
        while let Some(row) = rows.next()? {
            count += 1;
            ensure(count <= MAX_SNAPSHOT_ROWS_V1, "CMH2_SOURCE_STATE_ROWS")?;
            if count % 256 == 1 {
                live(deadline)?;
            }
            let bytes = dimension(row, 0, "text", false, MAX_SNAPSHOT_KEY_BYTES_V1 as u64)?
                + dimension(row, 2, "blob", false, MAX_SNAPSHOT_VALUE_BYTES_V1 as u64)?;
            admitted.charge(bytes)?;
        }
        live(deadline)
    }

    /// Produce a complete content observation from the existing read owner.
    /// The caller selects its context independently and may pin the result for
    /// later readback. The selected old checkpoint alone is not a new byte pin.
    pub fn observe_migration_history_v2(
        &self,
        pins: SourcePins,
        context: &ContentContextV1,
        budget: &mut ContentReadBudget,
        deadline: Instant,
    ) -> Result<ObservedContentV1> {
        self.with_migration_history_v2(pins, deadline, |source| {
            observe_migration_history_with_progress_v2(context, budget, source, &mut || {
                if Instant::now() < deadline {
                    Ok(())
                } else {
                    Err(SnapshotContentErrorV1::Input("history deadline"))
                }
            })
            .map_err(content_error)
        })
    }

    /// Match an independently retained complete CCH1/CMH2 expectation against
    /// fresh actual source bytes. No returned value authorizes migration/use.
    pub fn verify_migration_history_v2(
        &self,
        pins: SourcePins,
        expected: &ContentClaimV1,
        budget: &mut ContentReadBudget,
        deadline: Instant,
    ) -> Result<MigrationHistoryReadbackV2> {
        self.with_migration_history_v2(pins, deadline, |source| {
            verify_migration_history_with_progress_v2(expected, budget, source, &mut || {
                if Instant::now() < deadline {
                    Ok(())
                } else {
                    Err(SnapshotContentErrorV1::Input("history deadline"))
                }
            })
            .map_err(content_error)
        })
    }

    fn with_migration_history_v2<T>(
        &self,
        pins: SourcePins,
        deadline: Instant,
        inspect: impl for<'a> FnOnce(MigrationHistorySourceV2<'a>) -> Result<T>,
    ) -> Result<T> {
        ensure(
            deadline
                .checked_duration_since(Instant::now())
                .is_some_and(|left| !left.is_zero() && left <= MAX_MIGRATION_HISTORY_DURATION_V2),
            "CMH2_DEADLINE_BOUND",
        )?;
        ensure(
            !self.settings.app.is_pq_account_profile(),
            "CMH2_SOURCE_PROFILE",
        )?;
        ensure(
            self.state_backend != StateBackend::PermanentAccountGrowthV2,
            "GROWTH_COMPLETE_STATE_UNAVAILABLE",
        )?;
        ensure(
            pins.network == self.settings.network()
                && pins.genesis == self.settings.genesis()
                && pins.checkpoint != [0; 32],
            "CMH2_SOURCE_PINS",
        )?;
        self.namespace()?;
        let tx = self.db.unchecked_transaction()?;
        let changes = tx.total_changes();
        self.storage_context()?;
        self.ready()?;
        live(deadline)?;
        let height = self.record(pins.checkpoint)?.height;
        ensure(
            height <= MAX_MIGRATION_HISTORY_BLOCKS_V2 as u64,
            "CMH2_BLOCK_LIMIT",
        )?;
        let genesis = self.record(pins.genesis)?;
        let no_genesis_packet: bool = self.db.query_row(
            "SELECT packet IS NULL FROM blocks WHERE id=?",
            [pins.genesis.as_slice()],
            |row| row.get(0),
        )?;
        ensure(
            genesis.parent.is_none()
                && genesis.height == 0
                && genesis.work.bytes() == [0; 64]
                && no_genesis_packet,
            "CMH2_GENESIS_RECORD",
        )?;
        // The finite selected branch only. No paging cutoff or missing source
        // can turn a longer/incomplete chain into a complete CMH2 observation.
        let mut ancestry = Vec::with_capacity(height as usize);
        let mut current = pins.checkpoint;
        for expected_height in (1..=height).rev() {
            live(deadline)?;
            // Check the bounded retained-header/trace projection and actual
            // parent record before packet() may allocate the complete body.
            let header = self.stored_header(current)?;
            ensure(header.height == expected_height, "CMH2_ANCESTRY_HEIGHT")?;
            let packet = self.packet(current)?;
            ensure(packet.header == header, "CMH2_HEADER_READBACK")?;
            let trace = packet
                .proof
                .last_chunk::<32>()
                .copied()
                .ok_or("WORK_LENGTH")?;
            ancestry.push((current, packet.header, trace));
            current = header.parent;
        }
        ensure(current == pins.genesis, "CMH2_ANCESTRY_ENDPOINT")?;
        ancestry.reverse();
        let mut admitted = SourceAdmission::default();
        self.preflight_migration_state_inputs_v2(pins.genesis, &mut admitted, deadline)?;
        for (id, _, _) in &ancestry {
            self.preflight_migration_state_inputs_v2(*id, &mut admitted, deadline)?;
        }
        let active = self.active()?.0;
        if active == pins.genesis || ancestry.iter().any(|(id, _, _)| *id == active) {
            self.preflight_migration_active_inputs_v2(&mut admitted, deadline)?;
        }
        let initial = self.state_at_with_progress(pins.genesis, &mut || live(deadline))?;
        ensure(initial == self.settings.initial, "CMH2_GENESIS_STATE")?;
        let mut retained = 0;
        reserve_state(
            &mut retained,
            migration_history_snapshot_size_v2(&initial, &self.settings.app)
                .map_err(content_error)?,
        )?;
        let mut contents = Vec::with_capacity(height as usize);
        for (id, header, trace) in ancestry {
            let state = self.state_at_with_progress(id, &mut || live(deadline))?;
            live(deadline)?;
            reserve_state(
                &mut retained,
                migration_history_snapshot_size_v2(&state, &self.settings.app)
                    .map_err(content_error)?,
            )?;
            contents.push((header, trace, state));
        }
        let blocks: Vec<_> = contents
            .iter()
            .map(|(header, trace, state)| MigrationHistoryBlockV2 {
                header,
                trace: *trace,
                state,
            })
            .collect();
        live(deadline)?;
        let result = inspect(MigrationHistorySourceV2 {
            configuration: &self.settings.app,
            genesis: pins.genesis,
            genesis_timestamp: self.settings.genesis_time(),
            initial_state: &initial,
            checkpoint: pins.checkpoint,
            blocks: &blocks,
        })?;
        live(deadline)?;
        if tx.total_changes() != changes {
            self.invalidate_commitment();
            return Err(Error::from("CMH2_UNEXPECTED_WRITE").local_integrity());
        }
        tx.rollback()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
