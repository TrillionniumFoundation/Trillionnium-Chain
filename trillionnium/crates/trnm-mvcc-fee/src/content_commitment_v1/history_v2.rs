//! CMH2: bounded full-state ancestry byte readback in a fresh namespace.
//!
//! This observes the actual genesis State/configuration and every complete
//! Header, trace and State/configuration from height one to the selected tip.
//! Original SHA-256 genesis, parent and state-root relations are checked for
//! consistency; they are not upgraded into historical truth by this new hash.
//! Transaction/proof/receipt bodies, external objects named by state rows,
//! prior key ownership and local effect/revocation journals are not migrated.
//! No work, transaction execution, finality, cutover or retirement is authorized.

use super::{require, Config, Result, SnapshotContentErrorV1, SnapshotReader, State};
use crate::pon_executor::root_for_config;
use std::{
    collections::VecDeque,
    io::{self, Cursor, Read},
};
use trnm_protocol::{
    content_commitment::{
        observe_reader, ContentClaimV1, ContentContextV1, ContentKind, ContentReadBudget,
        ObservedContentV1,
    },
    pon_wire::{hash, Hash, Header},
};

/// A finite candidate archive, never an automatic truncation of a longer chain.
pub const MAX_MIGRATION_HISTORY_BLOCKS_V2: usize = 32;
pub const MAX_MIGRATION_HISTORY_BYTES_V2: u64 = 32 * 1024 * 1024;

/// Borrowed complete content, not evidence of how the block or State arose.
#[derive(Clone, Copy)]
pub struct MigrationHistoryBlockV2<'a> {
    pub header: &'a Header,
    pub trace: Hash,
    pub state: &'a State,
}

/// Complete height-zero through selected-tip material for the supported legacy
/// genesis grammar. There is no genesis Packet, and there is no omitted prefix.
/// The checkpoint is a compatibility locator; only a separately pinned complete
/// CCH1 claim can be an expected CMH2 byte commitment.
#[derive(Clone, Copy)]
pub struct MigrationHistorySourceV2<'a> {
    pub configuration: &'a Config,
    pub genesis: Hash,
    pub genesis_timestamp: u64,
    pub initial_state: &'a State,
    pub checkpoint: Hash,
    pub blocks: &'a [MigrationHistoryBlockV2<'a>],
}

/// A fixed-format encoding size for admission/memory accounting only. This
/// neither observes the complete bytes nor checks historical authorization.
pub fn migration_history_snapshot_size_v2(state: &State, cfg: &Config) -> Result<u64> {
    let (_, length) = SnapshotReader::new(state, cfg, Vec::new())?;
    require(
        length <= MAX_MIGRATION_HISTORY_BYTES_V2,
        "history snapshot size",
    )?;
    Ok(length)
}

struct Segment<'a> {
    prefix: Cursor<Vec<u8>>,
    state: SnapshotReader<'a>,
}

impl Read for Segment<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.prefix.read(output)?;
        if count != 0 {
            return Ok(count);
        }
        self.state.read(output)
    }
}

struct HistoryReader<'a, 'p> {
    segments: VecDeque<Segment<'a>>,
    progress: &'p mut dyn FnMut() -> Result<()>,
}

impl Read for HistoryReader<'_, '_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            // Check even on the last EOF probe: cancellation cannot complete a
            // read merely because all declared content bytes were delivered.
            (self.progress)().map_err(io::Error::other)?;
            let Some(segment) = self.segments.front_mut() else {
                return Ok(0);
            };
            let count = segment.read(output)?;
            if count != 0 {
                return Ok(count);
            }
            self.segments.pop_front();
        }
    }
}

fn checked_length(total: u64, extra: u64) -> Result<u64> {
    let next = total
        .checked_add(extra)
        .ok_or(SnapshotContentErrorV1::Input("history length overflow"))?;
    require(
        next <= MAX_MIGRATION_HISTORY_BYTES_V2,
        "history content size",
    )?;
    Ok(next)
}

fn snapshot<'a>(state: &'a State, cfg: &Config, mut prefix: Vec<u8>) -> Result<(Segment<'a>, u64)> {
    let (reader, length) = SnapshotReader::new(state, cfg, Vec::new())?;
    prefix.extend_from_slice(&length.to_be_bytes());
    let total = checked_length(length, prefix.len() as u64)?;
    Ok((
        Segment {
            prefix: Cursor::new(prefix),
            state: reader,
        },
        total,
    ))
}

fn prepare<'a>(
    source: MigrationHistorySourceV2<'a>,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<(VecDeque<Segment<'a>>, u64)> {
    progress()?;
    require(
        source.blocks.len() <= MAX_MIGRATION_HISTORY_BLOCKS_V2,
        "history block count",
    )?;
    let cfg = source.configuration;
    require(
        cfg.network != [0; 32]
            && cfg.parameters != [0; 32]
            && source.genesis != [0; 32]
            && source.checkpoint != [0; 32]
            && source.genesis_timestamp > 0
            && cfg.params["genesis_timestamp"].as_u64() == Some(source.genesis_timestamp),
        "history source context",
    )?;
    let mut prefix = b"CMH2".to_vec();
    for value in [
        cfg.network,
        cfg.parameters,
        source.genesis,
        source.checkpoint,
    ] {
        prefix.extend_from_slice(&value);
    }
    prefix.extend_from_slice(&source.genesis_timestamp.to_be_bytes());
    prefix.extend_from_slice(&(source.blocks.len() as u64).to_be_bytes());
    // SnapshotReader validates all supported configuration and row encodings
    // before the existing root calculation. Its row/configuration bounds stay.
    let (initial, mut length) = snapshot(source.initial_state, cfg, prefix)?;
    let initial_root =
        root_for_config(source.initial_state, cfg).map_err(SnapshotContentErrorV1::Input)?;
    require(
        source.genesis
            == hash(
                b"genesis",
                &[
                    &cfg.network,
                    &cfg.parameters,
                    &initial_root,
                    &source.genesis_timestamp.to_le_bytes(),
                ],
            ),
        "history genesis material",
    )?;
    let mut segments = VecDeque::with_capacity(source.blocks.len() + 1);
    segments.push_back(initial);
    let mut previous = source.genesis;
    for (index, block) in source.blocks.iter().enumerate() {
        progress()?;
        let height = (index as u64)
            .checked_add(1)
            .ok_or(SnapshotContentErrorV1::Input("history height overflow"))?;
        require(
            block.header.network == cfg.network
                && block.header.parameters == cfg.parameters
                && block.header.height == height
                && block.header.parent == previous,
            "history header ancestry",
        )?;
        let mut entry = b"HST2".to_vec();
        entry.extend_from_slice(&height.to_be_bytes());
        entry.extend_from_slice(&block.header.encode());
        entry.extend_from_slice(&block.trace);
        let (state, bytes) = snapshot(block.state, cfg, entry)?;
        length = checked_length(length, bytes)?;
        require(
            root_for_config(block.state, cfg).map_err(SnapshotContentErrorV1::Input)?
                == block.header.state,
            "history state root",
        )?;
        previous = block.header.block_id(block.trace);
        segments.push_back(state);
        progress()?;
    }
    require(previous == source.checkpoint, "history checkpoint endpoint")?;
    progress()?;
    Ok((segments, length))
}

/// Observe CMH2 with bounded streaming and complete EOF. Actual states remain
/// immutably borrowed; only per-segment configuration and one row are encoded,
/// never a second entire history byte string. This is not replay verification.
pub fn observe_migration_history_v2(
    context: &ContentContextV1,
    budget: &mut ContentReadBudget,
    source: MigrationHistorySourceV2<'_>,
) -> Result<ObservedContentV1> {
    observe_migration_history_with_progress_v2(context, budget, source, &mut || Ok(()))
}

/// The owner supplies cooperative cancellation/deadlines. Checks run between
/// bounded state preparation/root calculations and every read, including EOF.
/// This is not hard preemption of a root calculation or a process RSS limit.
pub fn observe_migration_history_with_progress_v2(
    context: &ContentContextV1,
    budget: &mut ContentReadBudget,
    source: MigrationHistorySourceV2<'_>,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<ObservedContentV1> {
    require(
        context.kind() == ContentKind::MigrationCheckpoint,
        "history content kind",
    )?;
    let (segments, length) = prepare(source, progress)?;
    let mut reader = HistoryReader { segments, progress };
    Ok(observe_reader(context, budget, length, &mut reader)?)
}

/// A matched independently pinned full-byte history. It has no public
/// constructor/deserializer and cannot be converted into a migration anchor.
///
/// ```compile_fail
/// use trnm_mvcc_fee::content_commitment_v1::MigrationHistoryReadbackV2;
/// use trnm_protocol::content_commitment::ObservedContentV1;
/// fn promote_a_digest(value: ObservedContentV1) -> MigrationHistoryReadbackV2 {
///     value
/// }
/// ```
#[derive(Debug)]
pub struct MigrationHistoryReadbackV2 {
    observation: ObservedContentV1,
    block_count: u64,
    checkpoint: Hash,
}

impl MigrationHistoryReadbackV2 {
    pub fn observation(&self) -> &ObservedContentV1 {
        &self.observation
    }
    pub fn block_count(&self) -> u64 {
        self.block_count
    }
    pub fn checkpoint(&self) -> Hash {
        self.checkpoint
    }
}

pub fn verify_migration_history_v2(
    expected: &ContentClaimV1,
    budget: &mut ContentReadBudget,
    source: MigrationHistorySourceV2<'_>,
) -> Result<MigrationHistoryReadbackV2> {
    verify_migration_history_with_progress_v2(expected, budget, source, &mut || Ok(()))
}

/// A checkpoint ID supplied alongside untrusted history is never the expected
/// commitment. The caller must retain this complete CCH1 pin independently.
pub fn verify_migration_history_with_progress_v2(
    expected: &ContentClaimV1,
    budget: &mut ContentReadBudget,
    source: MigrationHistorySourceV2<'_>,
    progress: &mut dyn FnMut() -> Result<()>,
) -> Result<MigrationHistoryReadbackV2> {
    let observation =
        observe_migration_history_with_progress_v2(expected.context(), budget, source, progress)?;
    expected.verify(&observation)?;
    Ok(MigrationHistoryReadbackV2 {
        observation,
        block_count: source.blocks.len() as u64,
        checkpoint: source.checkpoint,
    })
}

#[cfg(test)]
mod tests;
