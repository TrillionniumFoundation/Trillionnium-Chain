//! Durable, reference-backed authenticated-state research checkpoints.
//!
//! This sidecar has a fresh database namespace. Only an actual native genesis or
//! a block already retained by Node can be imported. Successor publication runs
//! the authenticated execution relation itself and compares its complete state
//! and receipts with that native block. Caller-supplied observations grant no
//! publication authority. Deltas, their checkpoint and optional active selection
//! share one SQLite transaction; AccountArchive and Node are read-only sources.
//!
//! Reconstructing a checkpoint still reads its bounded ancestor history and full
//! State. Native state, account sums and roots remain independent references.
//! This is not an installed Node backend, proof-availability service, chainwork
//! selector or production storage qualification. Logical quotas do not bound the
//! physical database/WAL allocation, and no pruning or local-operation rollback
//! is provided here.
use crate::account_archive_execution::{
    self,
    state_witness::{commitment_from_complete_state, StateCommitment, StateWitnessProgress},
    BlockInput, CheckedExecutionError, StateExecutionInput,
};
use crate::account_archive_prototype::{AccountArchive, ArchiveError, Context};
use crate::store::authenticated_state::{self as storage, Database};
use crate::{sequence_root, Node};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};
use trnm_mvcc_fee::pon_executor::State;
use trnm_protocol::pon_wire::{hash, Hash};

pub const SCHEMA: &str = "pon-authenticated-state-archive-v1";
pub const CHECKPOINT_SCHEMA: &str = "pon-authenticated-state-checkpoint-v1";
const MAX_STATE_KEYS: usize = 65_536;
const MAX_ROW_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    Context,
    Source,
    MissingCheckpoint,
    CorruptRecord,
    Conflict,
    StaleActive,
    Budget,
    Cancelled,
    Execution(CheckedExecutionError),
    Archive(ArchiveError),
    Native(crate::Error),
    Storage(rusqlite::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}
impl From<crate::Error> for Error {
    fn from(value: crate::Error) -> Self {
        Self::Native(value)
    }
}
impl From<ArchiveError> for Error {
    fn from(value: ArchiveError) -> Self {
        Self::Archive(value)
    }
}
impl From<CheckedExecutionError> for Error {
    fn from(value: CheckedExecutionError) -> Self {
        if value == CheckedExecutionError::Cancelled {
            Self::Cancelled
        } else {
            Self::Execution(value)
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;

/// Explicit logical quotas, checked before accepting existing data and before
/// committing new rows. Historical state reconstruction remains bounded by both
/// max_history and max_checkpoints; it is not constant-cost or succinct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Limits {
    pub max_checkpoints: u64,
    pub max_delta_rows: u64,
    pub max_payload_bytes: u64,
    pub max_history: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_checkpoints: 2048,
            max_delta_rows: 1_000_000,
            max_payload_bytes: 256 * 1024 * 1024,
            max_history: 2048,
        }
    }
}
impl Limits {
    pub(crate) fn check(self) -> Result<()> {
        if self.max_checkpoints == 0
            || self.max_delta_rows == 0
            || self.max_payload_bytes == 0
            || self.max_history == 0
            || self.max_checkpoints > i64::MAX as u64
            || self.max_delta_rows > i64::MAX as u64
            || self.max_payload_bytes > i64::MAX as u64
        {
            return Err(Error::Budget);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ActiveCheckpoint {
    pub checkpoint: Hash,
    /// Monotonic local selection generation; selecting an older branch never
    /// restores an old generation or alters any native local-operation history.
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    Inactive,
    Activate { expected: Option<ActiveCheckpoint> },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Observation {
    pub checkpoint_rows: u64,
    pub delta_rows: u64,
    pub snapshot_rows: u64,
    /// Sum of stored checkpoint, delta and snapshot payload lengths. SQLite
    /// pages, indexes and WAL bytes are deliberately not represented by this.
    pub payload_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    BeforeRead,
    ReadCheckpoint { index: usize },
    AfterRead,
    BeforeNativeBinding,
    AfterNativeBinding,
    Execution(StateWitnessProgress),
    BeforeTransaction,
    AfterBegin,
    DeltaWritten { index: usize },
    CheckpointWritten,
    SelectionWritten,
    BeforeCommit,
}
pub(crate) fn check(
    progress: &(impl Fn(Progress) -> bool + Sync + ?Sized),
    point: Progress,
) -> Result<()> {
    if progress(point) {
        Ok(())
    } else {
        Err(Error::Cancelled)
    }
}

/// Observation returned only after the actual stored source has been checked.
/// It cannot be constructed by deserializing an untrusted checkpoint claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Checkpoint {
    record: Record,
}
impl Checkpoint {
    pub fn id(&self) -> Hash {
        self.record.id
    }
    pub fn branch(&self) -> Hash {
        self.record.branch
    }
    pub fn parent(&self) -> Option<Hash> {
        self.record.parent
    }
    pub fn height(&self) -> u64 {
        self.record.height
    }
    pub fn commitment(&self) -> &StateCommitment {
        &self.record.commitment
    }
    pub fn delta_count(&self) -> u64 {
        self.record.delta_count
    }
    pub fn receipts(&self) -> &[Vec<u8>] {
        self.record
            .execution
            .as_ref()
            .map_or(&[], |execution| execution.receipts.as_slice())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredValue {
    value: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Delta {
    key: String,
    before: Option<StoredValue>,
    after: Option<StoredValue>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionRecord {
    archive_parent: Hash,
    native_parent: Hash,
    packet_digest: Hash,
    transactions_root: Hash,
    miner: Hash,
    receipts: Vec<Vec<u8>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub schema: String,
    pub id: Hash,
    pub branch: Hash,
    pub parent: Option<Hash>,
    pub height: u64,
    pub commitment: StateCommitment,
    pub delta_root: Hash,
    pub delta_count: u64,
    pub snapshot_digest: Option<Hash>,
    pub execution: Option<ExecutionRecord>,
}
impl Record {
    pub(crate) fn digest(&self) -> Result<Hash> {
        let bytes = encode(&(
            &self.schema,
            self.branch,
            self.parent,
            self.height,
            &self.commitment,
            self.delta_root,
            self.delta_count,
            self.snapshot_digest,
            &self.execution,
        ))?;
        Ok(hash(b"authenticated-state-checkpoint-v1", &[&bytes]))
    }
    pub(crate) fn validate(&self, context: Context) -> Result<()> {
        if self.schema != CHECKPOINT_SCHEMA
            || self.commitment.network != context.network
            || self.commitment.parameters != context.parameters
            || self.commitment.genesis != context.genesis
            || self.id != self.digest()?
            || self.delta_count > MAX_STATE_KEYS as u64 * 2
        {
            return Err(Error::CorruptRecord);
        }
        let initial = self.height == 0;
        if initial != self.parent.is_none()
            || initial != self.snapshot_digest.is_some()
            || initial != self.execution.is_none()
            || (initial && (self.branch != context.genesis || self.delta_count != 0))
        {
            return Err(Error::CorruptRecord);
        }
        Ok(())
    }
}
pub(crate) fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::CorruptRecord)?;
    if bytes.len() > MAX_ROW_BYTES {
        return Err(Error::Budget);
    }
    Ok(bytes)
}
pub(crate) fn decode<T>(bytes: &[u8]) -> Result<T>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_ROW_BYTES {
        return Err(Error::Budget);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| Error::CorruptRecord)?;
    if encode(&value)? != bytes {
        return Err(Error::CorruptRecord);
    }
    Ok(value)
}
pub(crate) struct Prepared {
    pub record: Record,
    pub deltas: Vec<Vec<u8>>,
    pub snapshot: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
pub struct PublishInput<'a> {
    pub parent: Hash,
    /// Actual block id already retained by the supplied Node.
    pub child: Hash,
    pub archive_parent: Hash,
    pub evidence: StateExecutionInput<'a>,
    pub selection: Selection,
}

pub struct AuthenticatedStateArchive {
    db: Database,
    context: Context,
    limits: Limits,
}
fn context(node: &Node) -> Context {
    Context {
        network: node.settings().network(),
        parameters: node.settings().parameters(),
        genesis: node.settings().genesis(),
    }
}
impl AuthenticatedStateArchive {
    pub fn open(path: &Path, node: &Node, limits: Limits) -> Result<Self> {
        Self::open_with_progress(path, node, limits, &|_| true)
    }
    /// Reopen validates every retained payload and native block binding. The
    /// selected complete state is reconstructed and checked before returning.
    /// Inactive states receive the same full check when read or selected.
    pub fn open_with_progress(
        path: &Path,
        node: &Node,
        limits: Limits,
        progress: &(impl Fn(Progress) -> bool + Sync),
    ) -> Result<Self> {
        check(progress, Progress::BeforeRead)?;
        let context = context(node);
        let result = Self {
            db: Database::open(path, context, limits)?,
            context,
            limits,
        };
        result.db.read(|db| {
            for (index, id) in storage::ids(db)?.into_iter().enumerate() {
                check(progress, Progress::ReadCheckpoint { index })?;
                let loaded = storage::load(db, context, id)?;
                let parent = loaded
                    .record
                    .parent
                    .map(|id| storage::load_record(db, context, id))
                    .transpose()?;
                validate_native(node, &loaded.record, parent.as_ref())?;
            }
            if let Some(active) = storage::active(db)? {
                materialize(db, node, context, limits, active.checkpoint, progress)?;
            }
            Ok(())
        })?;
        check(progress, Progress::AfterRead)?;
        Ok(result)
    }
    fn source(&self, node: &Node) -> Result<()> {
        if context(node) != self.context {
            return Err(Error::Context);
        }
        Ok(())
    }
    pub fn active(&self) -> Result<Option<ActiveCheckpoint>> {
        self.db.read(storage::active)
    }
    pub fn observation(&self) -> Result<Observation> {
        self.db.read(storage::observation)
    }
    pub fn read(&self, node: &Node, id: Hash) -> Result<(Checkpoint, State)> {
        self.read_with_progress(node, id, &|_| true)
    }
    pub fn read_with_progress(
        &self,
        node: &Node,
        id: Hash,
        progress: &(impl Fn(Progress) -> bool + Sync),
    ) -> Result<(Checkpoint, State)> {
        self.source(node)?;
        check(progress, Progress::BeforeRead)?;
        let result = self
            .db
            .read(|db| materialize(db, node, self.context, self.limits, id, progress))?;
        check(progress, Progress::AfterRead)?;
        Ok(result)
    }
    pub fn read_active(&self, node: &Node) -> Result<Option<(ActiveCheckpoint, State)>> {
        self.source(node)?;
        self.db.read(|db| {
            storage::active(db)?
                .map(|active| {
                    let (_, state) = materialize(
                        db,
                        node,
                        self.context,
                        self.limits,
                        active.checkpoint,
                        &|_| true,
                    )?;
                    Ok((active, state))
                })
                .transpose()
        })
    }
    pub fn import_genesis(
        &mut self,
        node: &Node,
        archive: &AccountArchive,
        archive_checkpoint: Hash,
        selection: Selection,
    ) -> Result<Checkpoint> {
        self.import_genesis_with_progress(node, archive, archive_checkpoint, selection, &|_| true)
    }
    pub fn import_genesis_with_progress(
        &mut self,
        node: &Node,
        archive: &AccountArchive,
        archive_checkpoint: Hash,
        selection: Selection,
        progress: &(impl Fn(Progress) -> bool + Sync),
    ) -> Result<Checkpoint> {
        self.source(node)?;
        check(progress, Progress::BeforeNativeBinding)?;
        let state = node.state_at(self.context.genesis)?;
        let source = archive.checkpoint(archive_checkpoint)?;
        if source.branch() != self.context.genesis || source.height() != 0 {
            return Err(Error::Source);
        }
        let witness = account_archive_execution::prepare_state_witness(
            node.settings(),
            archive,
            archive_checkpoint,
            &state,
        )?;
        let snapshot = encode(&state)?;
        let mut record = Record {
            schema: CHECKPOINT_SCHEMA.into(),
            id: [0; 32],
            branch: self.context.genesis,
            parent: None,
            height: 0,
            commitment: witness.commitment,
            delta_root: sequence_root("authenticated-state-deltas-v1", &[]),
            delta_count: 0,
            snapshot_digest: Some(hash(b"authenticated-state-snapshot-v1", &[&snapshot])),
            execution: None,
        };
        if record.commitment != commitment_from_complete_state(node.settings(), &state)? {
            return Err(Error::Source);
        }
        record.id = record.digest()?;
        validate_native(node, &record, None)?;
        check(progress, Progress::AfterNativeBinding)?;
        self.db.publish(
            Prepared {
                record: record.clone(),
                deltas: Vec::new(),
                snapshot: Some(snapshot),
            },
            None,
            selection,
            progress,
        )?;
        Ok(Checkpoint { record })
    }
    pub fn publish(
        &mut self,
        node: &Node,
        archive: &AccountArchive,
        input: PublishInput<'_>,
    ) -> Result<Checkpoint> {
        self.publish_with_progress(node, archive, input, &|_| true)
    }
    pub fn publish_with_progress(
        &mut self,
        node: &Node,
        archive: &AccountArchive,
        input: PublishInput<'_>,
        progress: &(impl Fn(Progress) -> bool + Sync),
    ) -> Result<Checkpoint> {
        self.source(node)?;
        let (parent, before) = self.read_with_progress(node, input.parent, progress)?;
        check(progress, Progress::BeforeNativeBinding)?;
        let packet = node.packet(input.child)?;
        if packet.header.parent != parent.branch()
            || parent.height().checked_add(1) != Some(packet.header.height)
            || packet.header.network != self.context.network
            || packet.header.parameters != self.context.parameters
        {
            return Err(Error::Source);
        }
        if packet
            .header
            .height
            .checked_add(1)
            .and_then(|count| usize::try_from(count).ok())
            .is_none_or(|count| count > self.limits.max_history)
        {
            return Err(Error::Budget);
        }
        let executed = account_archive_execution::execute_with_state_witness_and_progress(
            node.settings(),
            archive,
            input.archive_parent,
            &before,
            BlockInput {
                transactions: &packet.transactions,
                height: packet.header.height,
                miner: packet.header.miner,
                parent_id: packet.header.parent,
            },
            input.evidence,
            &|point| {
                if progress(Progress::Execution(point)) {
                    Ok(())
                } else {
                    Err(CheckedExecutionError::Cancelled)
                }
            },
        )?;
        let observed = executed.state_observation;
        let output = executed.execution.output;
        if observed.parent != parent.record.commitment
            || output.root != packet.header.state
            || sequence_root("receipts", &output.receipts) != packet.header.receipts
            || output.state != node.state_at(input.child)?
            || observed.successor.commitment
                != commitment_from_complete_state(node.settings(), &output.state)?
        {
            return Err(Error::Source);
        }
        let mut deltas = Vec::with_capacity(
            observed.successor.account_changes.len() + observed.successor.non_account_changes.len(),
        );
        for change in observed.successor.account_changes {
            let account = |value| {
                serde_json::to_value(value)
                    .map(|value| StoredValue { value })
                    .map_err(|_| Error::CorruptRecord)
            };
            deltas.push(Delta {
                key: format!("account:{}", hex::encode(change.owner)),
                before: change.before.map(account).transpose()?,
                after: Some(account(change.after)?),
            });
        }
        for change in observed.successor.non_account_changes {
            deltas.push(Delta {
                key: change.key,
                before: change
                    .before
                    .map(|value| StoredValue { value: value.value }),
                after: change.after.map(|value| StoredValue { value: value.value }),
            });
        }
        deltas.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        let delta_bytes = deltas.iter().map(encode).collect::<Result<Vec<_>>>()?;
        let mut checked_after = before;
        apply(&mut checked_after, &deltas)?;
        if checked_after != output.state {
            return Err(Error::Source);
        }
        let mut record = Record {
            schema: CHECKPOINT_SCHEMA.into(),
            id: [0; 32],
            branch: input.child,
            parent: Some(parent.id()),
            height: packet.header.height,
            commitment: observed.successor.commitment,
            delta_root: sequence_root("authenticated-state-deltas-v1", &delta_bytes),
            delta_count: delta_bytes.len() as u64,
            snapshot_digest: None,
            execution: Some(ExecutionRecord {
                archive_parent: input.archive_parent,
                native_parent: packet.header.parent,
                packet_digest: hash(
                    b"authenticated-state-native-packet-v1",
                    &[&packet.encode()?],
                ),
                transactions_root: packet.header.transactions,
                miner: packet.header.miner,
                receipts: output.receipts,
            }),
        };
        record.id = record.digest()?;
        validate_native(node, &record, Some(&parent.record))?;
        check(progress, Progress::AfterNativeBinding)?;
        self.db.publish(
            Prepared {
                record: record.clone(),
                deltas: delta_bytes,
                snapshot: None,
            },
            Some(&parent.record),
            input.selection,
            progress,
        )?;
        Ok(Checkpoint { record })
    }
    /// Explicit sidecar branch selection, independently of native fork choice.
    /// No Node activation or irreversible operation record is changed here.
    pub fn activate(
        &mut self,
        node: &Node,
        expected: Option<ActiveCheckpoint>,
        checkpoint: Hash,
    ) -> Result<ActiveCheckpoint> {
        self.activate_with_progress(node, expected, checkpoint, &|_| true)
    }
    pub fn activate_with_progress(
        &mut self,
        node: &Node,
        expected: Option<ActiveCheckpoint>,
        checkpoint: Hash,
        progress: &(impl Fn(Progress) -> bool + Sync),
    ) -> Result<ActiveCheckpoint> {
        let (checked, _) = self.read_with_progress(node, checkpoint, progress)?;
        self.db.activate(expected, &checked.record, progress)
    }
}

fn validate_native(node: &Node, record: &Record, parent: Option<&Record>) -> Result<()> {
    record.validate(context(node))?;
    if let Some(execution) = &record.execution {
        let parent = parent.ok_or(Error::CorruptRecord)?;
        let packet = node.packet(record.branch)?;
        if record.parent != Some(parent.id)
            || parent.height.checked_add(1) != Some(record.height)
            || execution.native_parent != parent.branch
            || packet.header.parent != parent.branch
            || packet.header.height != record.height
            || packet.header.network != record.commitment.network
            || packet.header.parameters != record.commitment.parameters
            || packet.header.state != record.commitment.state_root
            || packet.header.miner != execution.miner
            || packet.header.transactions != execution.transactions_root
            || packet.header.transactions != sequence_root("transactions", &packet.transactions)
            || packet.header.receipts != sequence_root("receipts", &execution.receipts)
            || execution.packet_digest
                != hash(
                    b"authenticated-state-native-packet-v1",
                    &[&packet.encode()?],
                )
        {
            return Err(Error::Source);
        }
    } else if parent.is_some()
        || record.commitment
            != commitment_from_complete_state(node.settings(), &node.settings().initial)?
    {
        return Err(Error::Source);
    }
    Ok(())
}

fn apply(state: &mut State, deltas: &[Delta]) -> Result<()> {
    let mut previous: Option<&str> = None;
    for delta in deltas {
        if previous.is_some_and(|key| key >= delta.key.as_str())
            || delta.before == delta.after
            || state.get(&delta.key) != delta.before.as_ref().map(|value| &value.value)
        {
            return Err(Error::CorruptRecord);
        }
        previous = Some(&delta.key);
        match &delta.after {
            Some(value) => {
                state.insert(delta.key.clone(), value.value.clone());
            }
            None => {
                state.remove(&delta.key);
            }
        }
    }
    if state.len() > MAX_STATE_KEYS {
        return Err(Error::Budget);
    }
    Ok(())
}

fn materialize(
    db: &Connection,
    node: &Node,
    context: Context,
    limits: Limits,
    id: Hash,
    progress: &(impl Fn(Progress) -> bool + Sync),
) -> Result<(Checkpoint, State)> {
    let mut path = Vec::new();
    let mut seen = BTreeSet::new();
    let mut current = id;
    let (mut state, mut previous) = loop {
        if path.len() >= limits.max_history || !seen.insert(current) {
            return Err(Error::Budget);
        }
        check(progress, Progress::ReadCheckpoint { index: path.len() })?;
        let loaded = storage::load(db, context, current)?;
        if let Some(snapshot) = loaded.snapshot {
            let state: State = decode(&snapshot)?;
            if state.len() > MAX_STATE_KEYS
                || loaded.record.commitment
                    != commitment_from_complete_state(node.settings(), &state)?
                || state != node.state_at(loaded.record.branch)?
            {
                return Err(Error::CorruptRecord);
            }
            validate_native(node, &loaded.record, None)?;
            break (state, loaded.record);
        }
        current = loaded.record.parent.ok_or(Error::CorruptRecord)?;
        // Retain only checkpoint identifiers across history; payloads are loaded
        // one bounded block at a time during forward replay.
        path.push(loaded.record.id);
    };
    for (index, id) in path.into_iter().rev().enumerate() {
        check(progress, Progress::ReadCheckpoint { index })?;
        let loaded = storage::load(db, context, id)?;
        validate_native(node, &loaded.record, Some(&previous))?;
        let deltas = loaded
            .deltas
            .iter()
            .map(|bytes| decode(bytes))
            .collect::<Result<Vec<Delta>>>()?;
        apply(&mut state, &deltas)?;
        if loaded.record.commitment != commitment_from_complete_state(node.settings(), &state)? {
            return Err(Error::CorruptRecord);
        }
        previous = loaded.record;
    }
    if state != node.state_at(previous.branch)? {
        return Err(Error::Source);
    }
    Ok((Checkpoint { record: previous }, state))
}

#[cfg(test)]
#[path = "authenticated_state_archive_tests.rs"]
mod tests;
