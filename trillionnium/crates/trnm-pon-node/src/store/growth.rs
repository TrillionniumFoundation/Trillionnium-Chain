//! Native growth backend owned by the existing Node writer and native.sqlite.
//! Account leaves are never copied into KV/snapshots. A block retains its COW
//! root and complete bounded working partition; every fork root remains pinned.
//! Hot operations validate used paths under a cold-audited SQLite epoch. A
//! foreign data_version/schema change refuses service until a fresh cold audit.
use super::{
    bytes32, canonical, schema, Delta, NativeOwners, Node, StateBackend, StoredHeaderLink,
};
use crate::account_archive_execution::state_witness::{
    growth_commitment_from_complete_state_v2, native_growth, GrowthStateCommitmentV2,
    VerifiedGrowthStateCommitmentV2,
};
use crate::account_archive_prototype::{
    self as archive,
    multiproof::{self, CheckedMultiproof, Multiproof},
    native_store, Account, Checkpoint, Context,
};
use crate::{consensus, ensure, sequence_root, Error, Result, Settings};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Mutex;
use trnm_crypto_primitives::pon_work;
use trnm_mvcc_fee::{
    continuity_v1,
    pon_executor::{self, growth as limits, State},
};
use trnm_protocol::pon_growth::GrowthHeader;
use trnm_protocol::pon_wire::{Envelope, Hash, Header};
#[cfg(test)]
mod difference_tests;
mod observation;
pub(super) mod observer;
mod packet;
mod profile;
mod recovery;
#[cfg(test)]
mod tests;
mod work_checked;
pub use packet::GrowthPacket;
pub use recovery::GrowthProgress;
pub(crate) use work_checked::GrowthWorkCheckedPacket;

pub(crate) const DDL: &str = "CREATE TABLE archive_nodes(id BLOB PRIMARY KEY,data BLOB NOT NULL);\nCREATE TABLE growth_states(block BLOB PRIMARY KEY,data BLOB NOT NULL);";
const MAX_RECORD_BYTES: usize = 524_288;

pub(super) struct Epoch {
    version: u64,
    schema: BTreeMap<String, String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredState {
    commitment: GrowthStateCommitmentV2,
    accounts: native_store::Root,
    working: State,
    parent_commitment: Option<Hash>,
    deltas: Hash,
}
/// Only a Node operation in its audited SQLite epoch can produce this anchor.
pub(crate) struct CheckedRootSource {
    header_root: Hash,
    stored: StoredState,
}
impl CheckedRootSource {
    pub(crate) fn header_root(&self) -> Hash {
        self.header_root
    }
    pub(crate) fn commitment(&self) -> &GrowthStateCommitmentV2 {
        &self.stored.commitment
    }
    pub(crate) fn accounts(&self) -> &native_store::Root {
        &self.stored.accounts
    }
}
struct Parent {
    source: CheckedRootSource,
    verified: VerifiedGrowthStateCommitmentV2,
    checkpoint: Checkpoint,
    height: u64,
}
struct Executed {
    state: StoredState,
    deltas: Vec<Delta>,
    receipts: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GrowthObservation {
    pub block: Hash,
    pub commitment: GrowthStateCommitmentV2,
    pub working_keys: usize,
    pub permanent_accounts: u64,
}

/// One native read transaction binds the current generation, header commitment
/// and complete bounded working partition. Monetary adapters must select actual
/// rows from this result; caller-supplied amounts are never funding authority.
#[derive(Clone, Debug)]
pub struct GrowthWorkingSnapshot {
    pub block: Hash,
    pub generation: u64,
    pub height: u64,
    pub commitment: GrowthStateCommitmentV2,
    pub working: State,
}

pub(super) fn archive_error(error: archive::ArchiveError) -> Error {
    Error::from(format!("GROWTH_ARCHIVE:{error:?}"))
}
pub(super) fn execution_error(
    error: crate::account_archive_execution::CheckedExecutionError,
) -> Error {
    Error::from(format!("GROWTH_EXECUTION:{error:?}"))
}
fn context(settings: &Settings) -> Context {
    Context {
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
    }
}
fn working(state: &State) -> State {
    state
        .iter()
        .filter(|(key, _)| !key.starts_with("account:"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}
fn delta_hash(deltas: &[Delta]) -> Result<Hash> {
    Ok(trnm_protocol::pon_wire::hash(
        b"native-growth-deltas-v2",
        &[&canonical(&deltas)?],
    ))
}
#[cfg(test)]
fn difference(before: &State, after: &State) -> Result<Vec<Delta>> {
    difference_with_progress(before, after, &|_| Ok(()))
}
fn difference_with_progress(
    before: &State,
    after: &State,
    progress: &impl Fn(GrowthProgress) -> Result<()>,
) -> Result<Vec<Delta>> {
    // Both immutable inputs already have canonical key order. Merge their
    // iterators instead of allocating a third key tree and looking up each
    // value again. Keep the original Value comparison BEFORE serialization:
    // changing it to byte comparison would change this profile's delta bytes.
    let mut left = before.iter();
    let mut right = after.iter();
    let mut prior = left.next();
    let mut next = right.next();
    let mut deltas = Vec::new();
    let mut index = 0;
    loop {
        // Includes the final boundary: an expired/cancelled request cannot
        // return a complete delta after its last value comparison/encoding.
        progress(GrowthProgress::DeltaComparison { index })?;
        let (key, old, new) = match (prior, next) {
            (Some((old_key, old_value)), Some((new_key, new_value))) => {
                match old_key.cmp(new_key) {
                    std::cmp::Ordering::Less => {
                        prior = left.next();
                        (old_key, Some(old_value), None)
                    }
                    std::cmp::Ordering::Equal => {
                        prior = left.next();
                        next = right.next();
                        (old_key, Some(old_value), Some(new_value))
                    }
                    std::cmp::Ordering::Greater => {
                        next = right.next();
                        (new_key, None, Some(new_value))
                    }
                }
            }
            (Some((key, value)), None) => {
                prior = left.next();
                (key, Some(value), None)
            }
            (None, Some((key, value))) => {
                next = right.next();
                (key, None, Some(value))
            }
            (None, None) => break,
        };
        index += 1;
        if old != new {
            deltas.push((
                key.clone(),
                old.map(canonical).transpose()?,
                new.map(canonical).transpose()?,
            ));
        }
    }
    Ok(deltas)
}
fn load(db: &Connection, id: Hash) -> Result<StoredState> {
    let bytes: Vec<u8> = db
        .query_row(
            "SELECT substr(data,1,?) FROM growth_states WHERE block=?",
            params![MAX_RECORD_BYTES + 1, id.as_slice()],
            |r| r.get(0),
        )
        .optional()?
        .ok_or("GROWTH_ROOT_UNAVAILABLE")?;
    ensure(bytes.len() <= MAX_RECORD_BYTES, "GROWTH_RECORD_LIMIT")?;
    let value: StoredState = serde_json::from_slice(&bytes)?;
    ensure(canonical(&value)? == bytes, "GROWTH_RECORD_ENCODING")?;
    Ok(value)
}
fn save(db: &Connection, id: Hash, value: &StoredState) -> Result<()> {
    let bytes = canonical(value)?;
    ensure(bytes.len() <= MAX_RECORD_BYTES, "GROWTH_RECORD_LIMIT")?;
    ensure(
        db.execute(
            "INSERT INTO growth_states VALUES(?,?)",
            params![id.as_slice(), bytes],
        )? == 1,
        "STORAGE_WRITE",
    )?;
    ensure(load(db, id)? == *value, "STORAGE_WRITE").map_err(Error::local_integrity)
}
pub(super) fn initial_root(settings: &Settings) -> Result<Hash> {
    Ok(
        growth_commitment_from_complete_state_v2(settings, &settings.initial)
            .map_err(execution_error)?
            .id,
    )
}
pub(super) fn seed(db: &Connection, settings: &Settings) -> Result<()> {
    profile::require(settings)?;
    let accounts = native_store::seed_growth(db, &settings.initial)?;
    let commitment = growth_commitment_from_complete_state_v2(settings, &settings.initial)
        .map_err(execution_error)?;
    let state = StoredState {
        commitment: commitment.observation().clone(),
        accounts,
        working: working(&settings.initial),
        parent_commitment: None,
        deltas: delta_hash(&[])?,
    };
    save(db, settings.genesis(), &state)
}

impl Node {
    /// An explicitly selected fresh native namespace; the existing owner lock,
    /// WAL/FULL durability and atomic initialization remain in force.
    pub fn open_with_permanent_account_growth_v2(path: &Path, settings: Settings) -> Result<Self> {
        Self::open_growth_selected(path, settings, false, 1)
    }
    /// Select a bounded preparation pool. Only signatures/preparation use these
    /// workers; the existing Node owner still serializes all state and commits.
    /// The default opener and independent cold replay retain one worker.
    pub fn open_with_permanent_account_growth_v2_and_workers(
        path: &Path,
        settings: Settings,
        workers: usize,
    ) -> Result<Self> {
        Self::open_growth_selected(path, settings, false, workers)
    }
    /// Observe a locked existing namespace through a private SQLite snapshot.
    /// Any source WAL/SHM/rollback journal requires ordinary writer recovery.
    /// The default main-file copy limit is 8 GiB; history replay is not CPU-bounded.
    pub fn open_growth_packet_observer(path: &Path, settings: Settings) -> Result<Self> {
        Self::open_growth_packet_observer_with_snapshot_byte_limit(
            path,
            settings,
            observer::DEFAULT_SNAPSHOT_BYTE_LIMIT,
        )
    }
    /// A caller-selected local copy-byte limit, not consensus or reservation
    /// authority. No SQLite connection ever opens the source namespace.
    pub fn open_growth_packet_observer_with_snapshot_byte_limit(
        path: &Path,
        settings: Settings,
        snapshot_byte_limit: u64,
    ) -> Result<Self> {
        profile::require(&settings)?;
        ensure(
            !super::owner_marker_present(path)?,
            "OWNER_TASK_POLICY_REQUIRED",
        )?;
        let snapshot = observer::Snapshot::create(path, snapshot_byte_limit)?;
        let mut node = Self::open_growth_selected(snapshot.path(), settings, true, 1)?;
        snapshot.check()?;
        node.growth_observer_snapshot = Some(snapshot);
        Ok(node)
    }
    fn open_growth_selected(
        path: &Path,
        settings: Settings,
        observation_only: bool,
        workers: usize,
    ) -> Result<Self> {
        ensure([1, 2, 4, 8].contains(&workers), "GROWTH_WORKERS")?;
        profile::require(&settings)?;
        ensure(
            !super::owner_marker_present(path)?,
            "OWNER_TASK_POLICY_REQUIRED",
        )?;
        Self::open_selected(
            path,
            settings,
            workers,
            None,
            NativeOwners {
                policy: None,
                mining: None,
                continuous: None,
                pq_network: None,
                pq_witness: None,
            },
            StateBackend::PermanentAccountGrowthV2,
            observation_only,
        )
    }
    fn growth_guard(&self) -> Result<()> {
        ensure(
            self.state_backend == StateBackend::PermanentAccountGrowthV2,
            "GROWTH_BACKEND",
        )?;
        self.namespace()?;
        self.storage_context()?;
        let epoch = self.growth_epoch.as_ref().ok_or("GROWTH_AUDIT_REQUIRED")?;
        let version: u64 = self.db.query_row("PRAGMA data_version", [], |r| r.get(0))?;
        ensure(
            version == epoch.version && schema(&self.db)? == epoch.schema,
            "GROWTH_STORAGE_EPOCH_CHANGED",
        )
        .map_err(Error::local_integrity)
    }
    fn growth_parent(&self, id: Hash) -> Result<Parent> {
        let block = self.record(id)?;
        let stored = load(&self.db, id)?;
        let source = CheckedRootSource {
            header_root: block.root,
            stored,
        };
        let verified = native_growth::bind(&self.settings, &source, &source.stored.working)
            .map_err(execution_error)?;
        let checkpoint = native_store::query_growth_checkpoint(
            &self.db,
            context(&self.settings),
            id,
            block.height,
            block.root,
            &source.stored.accounts,
        )?;
        Ok(Parent {
            source,
            verified,
            checkpoint,
            height: block.height,
        })
    }
    pub fn growth_observe(&self, block: Hash) -> Result<GrowthObservation> {
        self.growth_guard()?;
        let tx = self.db.unchecked_transaction()?;
        let parent = self.growth_parent(block)?;
        let out = GrowthObservation {
            block,
            commitment: parent.verified.observation().clone(),
            working_keys: parent.source.stored.working.len(),
            permanent_accounts: parent.source.stored.accounts.count,
        };
        self.growth_guard()?;
        tx.rollback()?;
        Ok(out)
    }
    pub fn growth_account(&self, block: Hash, owner: Hash) -> Result<Option<Account>> {
        self.growth_guard()?;
        let tx = self.db.unchecked_transaction()?;
        let parent = self.growth_parent(block)?;
        let (proof, _) =
            multiproof::from_native_database(&self.db, &parent.checkpoint, &[owner], &|_| {
                Ok::<_, archive::ArchiveError>(())
            })
            .map_err(archive_error)?;
        let checked =
            CheckedMultiproof::verify(context(&self.settings), &parent.checkpoint, &proof)
                .map_err(archive_error)?;
        let value = checked.account(owner).map_err(archive_error)?;
        self.growth_guard()?;
        tx.rollback()?;
        Ok(value)
    }
    pub fn growth_working(&self, block: Hash) -> Result<State> {
        self.growth_guard()?;
        let tx = self.db.unchecked_transaction()?;
        let state = self.growth_parent(block)?.source.stored.working;
        self.growth_guard()?;
        tx.rollback()?;
        Ok(state)
    }
    pub fn growth_current_working(&self) -> Result<GrowthWorkingSnapshot> {
        self.growth_guard()?;
        let tx = self.db.unchecked_transaction()?;
        let result = self.growth_snapshot_in_read()?;
        self.growth_guard()?;
        tx.rollback()?;
        Ok(result)
    }
    /// Caller holds one read transaction for a multi-step native observation.
    pub(in crate::store) fn growth_snapshot_in_read(&self) -> Result<GrowthWorkingSnapshot> {
        self.growth_guard()?;
        let (block, generation) = self.active()?;
        let parent = self.growth_parent(block)?;
        Ok(GrowthWorkingSnapshot {
            block,
            generation,
            height: parent.height,
            commitment: parent.verified.observation().clone(),
            working: parent.source.stored.working,
        })
    }
    pub(in crate::store) fn growth_payment_epoch(&self) -> Result<()> {
        self.growth_guard()
    }
    /// Bounded historical working state for a caller-owned read snapshot. The
    /// complete working commitment and account-root checkpoint are still bound
    /// to the retained block; no permanent account enumeration is needed.
    pub(in crate::store) fn growth_working_in_read(&self, block: Hash) -> Result<State> {
        ensure(!self.db.is_autocommit(), "GROWTH_READ_SNAPSHOT_REQUIRED")?;
        self.growth_guard()?;
        Ok(self.growth_parent(block)?.source.stored.working)
    }
    pub(in crate::store) fn growth_observation_epoch(&self) -> Result<()> {
        self.growth_guard()
    }
    /// The evaluation reader has one guarded read snapshot for its entire
    /// ancestor walk. Check the PNP2 header/trace identity and both stored rows;
    /// the caller freshly assesses clock, chainwork and confirmation policy.
    pub(in crate::store) fn growth_evaluation_header_link(
        &self,
        id: Hash,
    ) -> Result<StoredHeaderLink> {
        ensure(!self.db.is_autocommit(), "GROWTH_READ_SNAPSHOT_REQUIRED")?;
        (|| {
            let header = self.growth_header(id)?.ledger;
            let record = self.record(id)?;
            ensure(
                header.network == self.settings.network()
                    && header.parameters == self.settings.parameters()
                    && record.parent == Some(header.parent)
                    && record.height == header.height
                    && record.root == header.state,
                "GROWTH_HEADER_RECORD",
            )?;
            let parent = self.record(header.parent)?;
            ensure(
                parent.height.checked_add(1) == Some(record.height),
                "ANCESTRY_HEIGHT",
            )?;
            Ok(StoredHeaderLink {
                header,
                record,
                parent_work: parent.work,
            })
        })()
        .map_err(Error::local_integrity)
    }
    /// Actual native point reads and compact witness construction. No full
    /// account enumeration is performed, and authenticated absence is explicit.
    pub fn growth_account_multiproof(
        &self,
        block: Hash,
        owners: &[Hash],
    ) -> Result<(Checkpoint, Multiproof, multiproof::ConstructionObservation)> {
        self.growth_guard()?;
        ensure(
            !owners.is_empty() && owners.len() <= limits::MAX_WITNESS_ACCOUNTS,
            "GROWTH_WITNESS_LIMIT",
        )?;
        let tx = self.db.unchecked_transaction()?;
        let parent = self.growth_parent(block)?;
        let (proof, observation) =
            multiproof::from_native_database(&self.db, &parent.checkpoint, owners, &|_| {
                Ok::<_, archive::ArchiveError>(())
            })
            .map_err(archive_error)?;
        GrowthPacket::witness_digest(&proof)?;
        CheckedMultiproof::verify(context(&self.settings), &parent.checkpoint, &proof)
            .map_err(archive_error)?;
        self.growth_guard()?;
        tx.rollback()?;
        Ok((parent.checkpoint, proof, observation))
    }
    pub fn growth_packet(&self, id: Hash) -> Result<GrowthPacket> {
        self.growth_guard()?;
        self.growth_load_packet(id)
    }
    fn growth_load_packet(&self, id: Hash) -> Result<GrowthPacket> {
        let raw: Vec<u8> = self.db.query_row(
            "SELECT substr(packet,1,?) FROM blocks WHERE id=?",
            params![limits::MAX_PACKET_BYTES + 1, id.as_slice()],
            |r| r.get(0),
        )?;
        let packet = GrowthPacket::decode(&raw)?;
        ensure(packet.id()? == id, "GROWTH_PACKET_ID")?;
        Ok(packet)
    }
    pub(in crate::store) fn growth_check_payment_transition(
        &self,
        id: Hash,
        observer: &dyn pon_executor::CanonicalTransitionObserver,
    ) -> Result<()> {
        self.growth_check_retained_transition(id, Some(observer))
    }
    fn growth_check_retained_transition(
        &self,
        id: Hash,
        observer: Option<&dyn pon_executor::CanonicalTransitionObserver>,
    ) -> Result<()> {
        self.growth_check_retained_transition_with_progress(id, observer, &|_| Ok(()))
    }
    fn growth_check_retained_transition_with_progress(
        &self,
        id: Hash,
        observer: Option<&dyn pon_executor::CanonicalTransitionObserver>,
        progress: &(impl Fn(GrowthProgress) -> Result<()> + Sync),
    ) -> Result<()> {
        progress(GrowthProgress::BeforeContext)?;
        self.growth_guard()?;
        let packet = self.growth_load_packet(id)?;
        self.check_growth_header_with_progress(&packet, u64::MAX, progress)?;
        let checked = GrowthWorkCheckedPacket::verify_with_progress(packet, progress)?;
        let (packet, _verified_work) = checked.into_parts();
        let parent = self.growth_parent(packet.header.ledger.parent)?;
        let executed = execute_observed(&self.settings, &parent, &packet, observer, progress)?;
        let stored = self.growth_parent(id)?;
        ensure(
            executed.state.commitment == stored.source.stored.commitment
                && executed.state.working == stored.source.stored.working
                && executed.state.parent_commitment == stored.source.stored.parent_commitment
                && executed.state.deltas == stored.source.stored.deltas
                && self.delta_rows_with_progress(id, &mut || {
                    progress(GrowthProgress::ObservationDelta)
                })? == executed.deltas
                && packet.header.ledger.state == executed.state.commitment.id
                && packet.header.ledger.receipts == sequence_root("receipts", &executed.receipts),
            "NATIVE_PAYMENT_TRANSITION",
        )?;
        self.growth_guard()
    }
    fn growth_header(&self, id: Hash) -> Result<GrowthHeader> {
        let width = 4 + trnm_protocol::pon_growth::GROWTH_HEADER_BYTES;
        let (prefix, trace, length): (Vec<u8>, Vec<u8>, usize) = self.db.query_row(
            "SELECT substr(packet,1,?),substr(packet,-32,32),length(packet) FROM blocks WHERE id=?",
            params![width, id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        ensure(
            prefix.len() == width
                && prefix[..4] == *b"PNP2"
                && (width + 2 + 4 + 44 + pon_work::PROOF_BYTES..=limits::MAX_PACKET_BYTES)
                    .contains(&length),
            "GROWTH_PACKET_LENGTH",
        )?;
        let header = GrowthHeader::decode(&prefix[4..]).map_err(|_| Error::from("HEADER_CODEC"))?;
        ensure(header.block_id(bytes32(trace)?) == id, "GROWTH_PACKET_ID")?;
        Ok(header)
    }
    fn growth_recent_with_progress(
        &self,
        mut id: Hash,
        progress: &(impl Fn(GrowthProgress) -> Result<()> + Sync),
    ) -> Result<Vec<(u64, Hash)>> {
        let maximum = self.settings.limit("retarget_interval")?.max(11) as usize;
        let mut recent = Vec::new();
        while id != self.settings.genesis() && recent.len() < maximum {
            progress(GrowthProgress::HeaderAncestor {
                index: recent.len(),
            })?;
            // The frozen storage epoch already checked each complete packet.
            // DAA only reads its fixed header and trace identity, never the
            // account witness and W1 body once per ancestor per request.
            let h = self.growth_header(id)?.ledger;
            let record = self.record(id)?;
            ensure(
                record.parent == Some(h.parent)
                    && record.height == h.height
                    && record.root == h.state,
                "GROWTH_HEADER_RECORD",
            )?;
            recent.push((h.timestamp, h.target));
            id = h.parent;
        }
        if id == self.settings.genesis() {
            recent.push((
                self.settings.genesis_time(),
                self.settings.target("initial_target_hex")?,
            ));
        }
        Ok(recent)
    }
    pub fn growth_expected_target(&self, parent: Hash) -> Result<Hash> {
        self.growth_guard()?;
        self.growth_target(parent)
    }
    fn growth_target(&self, parent: Hash) -> Result<Hash> {
        self.growth_target_with_progress(parent, &|_| Ok(()))
    }
    fn growth_target_with_progress(
        &self,
        parent: Hash,
        progress: &(impl Fn(GrowthProgress) -> Result<()> + Sync),
    ) -> Result<Hash> {
        let height = consensus::BranchTargetHeight::after(self.record(parent)?.height)?;
        let recent = self.growth_recent_with_progress(parent, progress)?;
        self.growth_target_from_recent(height, &recent)
    }
    // `recent` belongs to one current-owner header check. It is never retained
    // across W1 work, owner release, another request or a write transaction.
    fn growth_target_from_recent(
        &self,
        height: consensus::BranchTargetHeight,
        recent: &[(u64, Hash)],
    ) -> Result<Hash> {
        let interval = self.settings.limit("retarget_interval")?;
        match height.window(recent, interval)? {
            consensus::TargetWindow::Parent(target) => Ok(target),
            consensus::TargetWindow::Retarget {
                target,
                first,
                last,
            } => consensus::retarget(
                target,
                first,
                last,
                interval,
                self.settings.limit("target_spacing_seconds")?,
                self.settings.target("pow_limit_hex")?,
            ),
        }
    }
}

fn execute(
    settings: &Settings,
    parent: &Parent,
    packet: &GrowthPacket,
    progress: &(impl Fn(GrowthProgress) -> Result<()> + Sync),
) -> Result<Executed> {
    execute_observed(settings, parent, packet, None, progress)
}
fn execute_observed(
    settings: &Settings,
    parent: &Parent,
    packet: &GrowthPacket,
    observer: Option<&dyn pon_executor::CanonicalTransitionObserver>,
    progress: &(impl Fn(GrowthProgress) -> Result<()> + Sync),
) -> Result<Executed> {
    execute_observed_with_workers(settings, parent, packet, observer, (1, &()), progress)
}

fn execute_observed_with_workers(
    settings: &Settings,
    parent: &Parent,
    packet: &GrowthPacket,
    observer: Option<&dyn pon_executor::CanonicalTransitionObserver>,
    preparation: (usize, &dyn pon_executor::ExecutionWorkerAccounting),
    progress: &(impl Fn(GrowthProgress) -> Result<()> + Sync),
) -> Result<Executed> {
    let checked = CheckedMultiproof::verify_with_progress(
        context(settings),
        &parent.checkpoint,
        &packet.accounts,
        &|point| {
            progress(GrowthProgress::ParentProof(point))
                .map_err(super::NativeAccountProofFailure::Control)
        },
    )
    .map_err(|error| match error {
        super::NativeAccountProofFailure::Archive(error) => archive_error(error),
        super::NativeAccountProofFailure::Control(error) => error,
    })?;
    ensure(
        checked.len() <= limits::MAX_WITNESS_ACCOUNTS,
        "GROWTH_WITNESS_LIMIT",
    )?;
    // Reuse the original public request control while materializing this
    // bounded working partition. One full clone would defer cancellation and
    // the live CPU check until all retained values had been copied.
    // Collect fallibly before bulk map construction: Result<State> would
    // still sort/build the successful prefix after its iterator reports Err.
    // The temporary pair buffer is bounded by the existing working limits;
    // the bulk construction itself is not interruptible.
    let copied = parent
        .source
        .stored
        .working
        .iter()
        .enumerate()
        .map(|(index, (key, value))| {
            progress(GrowthProgress::WorkingCopy { index })?;
            Ok((key.clone(), value.clone()))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut view: State = copied.into_iter().collect();
    progress(GrowthProgress::WorkingCopy {
        index: parent.source.stored.working.len(),
    })?;
    for (index, (owner, value)) in checked.values().enumerate() {
        progress(GrowthProgress::WitnessAccount { index })?;
        if let Some(value) = value {
            view.insert(
                format!("account:{}", hex::encode(owner)),
                json!({"balance":value.balance,"nonce":value.nonce}),
            );
        }
    }
    progress(GrowthProgress::WitnessAccount {
        index: checked.len(),
    })?;
    let accessed = Mutex::new(BTreeSet::new());
    let access = |who: &str| -> pon_executor::Result<()> {
        let owner = crate::digest(who).map_err(|_| "GROWTH_ACCOUNT_KEY")?;
        checked
            .account(owner)
            .map_err(|_| "GROWTH_MISSING_ACCOUNT_WITNESS")?;
        accessed
            .lock()
            .map_err(|_| "GROWTH_OBSERVATION")?
            .insert(owner);
        Ok(())
    };
    let h = &packet.header.ledger;
    let partition = limits::AccountPartition {
        parent_count: parent.verified.permanent_account_count,
        parent_balance: parent.verified.permanent_account_balance,
    };
    // M06's existing commitment callback returns only relation strings. Keep
    // one original control error locally and restore it before interpreting
    // that legacy result; never retry or overwrite a failed control operation.
    let mut commitment_control_error = None;
    let result = limits::execute_with_commitment_observed_control(
        &view,
        pon_executor::BlockExecution {
            timestamp: None,
            transactions: &packet.transactions,
            height: h.height,
            miner: h.miner,
            parent_id: h.parent,
            workers: preparation.0,
        },
        &settings.app,
        limits::GrowthExecutionInputs {
            partition: &partition,
            account_access: &access,
            observer,
        },
        |_, next| {
            if commitment_control_error.is_some() {
                return Err("GROWTH_SUCCESSOR_COMMITMENT");
            }
            match native_growth::successor_with_progress(
                &parent.verified,
                &checked,
                next,
                &|point| progress(GrowthProgress::CommitmentProof(point)),
            ) {
                Ok(successor) => Ok(successor.id),
                Err(native_growth::NativeGrowthFailure::Relation(_)) => {
                    Err("GROWTH_SUCCESSOR_COMMITMENT")
                }
                Err(native_growth::NativeGrowthFailure::Control(error)) => {
                    commitment_control_error = Some(error);
                    Err("GROWTH_SUCCESSOR_COMMITMENT")
                }
            }
        },
        &pon_executor::ExecutionControl::new(
            &|point| progress(GrowthProgress::Execution(point)),
            preparation.1,
        ),
    );
    if let Some(error) = commitment_control_error {
        return Err(error);
    }
    let output = match result {
        Ok(value) => value,
        Err(pon_executor::ExecutionError::Relation(error)) => return Err(error.into()),
        Err(pon_executor::ExecutionError::Cancelled(error)) => return Err(error),
    };
    ensure(
        accessed
            .into_inner()
            .map_err(|_| "GROWTH_OBSERVATION")?
            .len()
            == checked.len(),
        "GROWTH_UNUSED_ACCOUNT_WITNESS",
    )?;
    let commitment = native_growth::successor_with_progress(
        &parent.verified,
        &checked,
        &output.state,
        &|point| progress(GrowthProgress::FinalSuccessorProof(point)),
    )
    .map_err(|error| match error {
        native_growth::NativeGrowthFailure::Relation(error) => execution_error(error),
        native_growth::NativeGrowthFailure::Control(error) => error,
    })?;
    let deltas = difference_with_progress(&view, &output.state, progress)?;
    // The canonical encoding and hash stay byte-identical to the original
    // profile. Boundaries do not claim interruption inside serde or hashing.
    progress(GrowthProgress::BeforeDeltaEncoding)?;
    let deltas_hash = delta_hash(&deltas)?;
    progress(GrowthProgress::AfterDeltaEncoding)?;
    // All fallible checks consumed the full executed state. Move its working
    // partition into storage instead of cloning every retained key and value.
    let mut working = output.state;
    working.retain(|key, _| !key.starts_with("account:"));
    let state = StoredState {
        commitment: commitment.observation().clone(),
        accounts: native_store::Root {
            node: None,
            digest: commitment.permanent_account_root,
            count: commitment.permanent_account_count,
            balance: commitment.permanent_account_balance,
        },
        working,
        parent_commitment: Some(parent.verified.id),
        deltas: deltas_hash,
    };
    Ok(Executed {
        state,
        deltas,
        receipts: output.receipts,
    })
}

fn requested(parent: &Parent, txs: &[Vec<u8>], miner: Hash) -> Result<Vec<Hash>> {
    let mut owners: BTreeSet<_> = limits::mandatory_owners(&parent.source.stored.working)?
        .into_iter()
        .map(|s| crate::digest(&s))
        .collect::<Result<_>>()?;
    owners.insert(miner);
    let envelopes = txs
        .iter()
        .map(|raw| Envelope::decode(raw).map_err(|_| Error::from("TRANSACTION_CODEC")))
        .collect::<Result<Vec<_>>>()?;
    let mut providers: BTreeMap<Vec<u8>, Hash> = BTreeMap::new();
    for envelope in &envelopes {
        if envelope.tag == 2 && envelope.payload.len() >= 64 {
            providers.insert(
                envelope.payload[..32].to_vec(),
                envelope.payload[32..64].try_into().map_err(|_| "LENGTH")?,
            );
        }
    }
    for envelope in &envelopes {
        owners.insert(envelope.sender);
        if envelope.tag == 1 {
            owners.insert(
                envelope
                    .payload
                    .get(..32)
                    .ok_or("LENGTH")?
                    .try_into()
                    .map_err(|_| "LENGTH")?,
            );
        } else if envelope.tag == 5 {
            let task = envelope.payload.get(..32).ok_or("LENGTH")?;
            let provider = parent
                .source
                .stored
                .working
                .get(&format!("task:{}", hex::encode(task)))
                .and_then(|row| row.get("provider"))
                .and_then(serde_json::Value::as_str)
                .map(crate::digest)
                .transpose()?
                .or_else(|| providers.get(task).copied())
                .ok_or("STATE")?;
            owners.insert(provider);
        }
    }
    ensure(
        owners.len() <= limits::MAX_WITNESS_ACCOUNTS,
        "GROWTH_WITNESS_LIMIT",
    )?;
    Ok(owners.into_iter().collect())
}
