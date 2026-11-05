//! Bounded, exact-input arithmetic for the original complete history reads.
//!
//! SQL observations, parent relations, stored work, cancellation and history
//! validity are never supplied by this module. Each use follows the original
//! typed SQL conversion/limit checks and compares the complete actual input.
//! Retained entries are immutable and never evicted by a scan. Once a pool is
//! full, new material is simply not retained; tip-to-genesis scans cannot evict
//! their own not-yet-visited candidates. This is bounded retained arithmetic,
//! not an unbounded history cache or an O(new suffix) database reader.
use super::{Delta, Record};
use crate::Settings;
use serde::Serialize;
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::mem::size_of;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread::{self, ThreadId};
use std::time::Instant;
use trnm_protocol::pon_wire::{Hash, Header};

const MAX_ENTRIES: usize = 64;
const MAX_POOL_CHARGE: usize = 4 * 1024 * 1024;
// Covers the Arc allocation, entry/key, Vec slot and conservative allocator
// bookkeeping. Owned dynamic capacities and boxed slice lengths are additional.
const ENTRY_OVERHEAD: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Key([Hash; 4]);
impl Key {
    fn new(settings: &Settings, block: Hash) -> Self {
        Self([
            settings.network(),
            settings.parameters(),
            settings.genesis(),
            block,
        ])
    }
}

struct Entry<T> {
    key: Key,
    value: T,
}
struct Pool<T> {
    entries: RefCell<Vec<Arc<Entry<T>>>>,
    charge: Cell<usize>,
}
impl<T> Default for Pool<T> {
    fn default() -> Self {
        Self {
            entries: RefCell::default(),
            charge: Cell::new(0),
        }
    }
}
impl<T> Pool<T> {
    fn get(&self, key: Key) -> Option<Arc<Entry<T>>> {
        self.entries
            .try_borrow()
            .ok()?
            .iter()
            .find(|entry| entry.key == key)
            .cloned()
    }
    fn can_retain(&self, key: Key) -> bool {
        self.entries.try_borrow().is_ok_and(|entries| {
            entries.len() < MAX_ENTRIES
                && self.charge.get() < MAX_POOL_CHARGE
                && !entries.iter().any(|entry| entry.key == key)
        })
    }
    fn retain(&self, key: Key, value: T, dynamic_charge: usize) {
        let Some(charge) = ENTRY_OVERHEAD
            .checked_add(size_of::<Entry<T>>())
            .and_then(|n| n.checked_add(dynamic_charge))
        else {
            return;
        };
        let Some(total) = self.charge.get().checked_add(charge) else {
            return;
        };
        if total > MAX_POOL_CHARGE {
            return;
        }
        if let Ok(mut entries) = self.entries.try_borrow_mut() {
            if entries.len() < MAX_ENTRIES && !entries.iter().any(|entry| entry.key == key) {
                entries.push(Arc::new(Entry { key, value }));
                self.charge.set(total);
            }
        }
    }
    fn status(&self) -> Value {
        json!({"entries":self.entries.try_borrow().ok().map(|entries|entries.len()),
            "retained_software_charge_bytes":self.charge.get(),
            "entry_limit":MAX_ENTRIES,"charge_limit_bytes":MAX_POOL_CHARGE})
    }
    #[cfg(test)]
    fn clear(&self) {
        self.entries.borrow_mut().clear();
        self.charge.set(0);
    }
}

struct RecordInput {
    bytes: Box<[u8]>,
    record: Record,
}
#[derive(Clone)]
pub(super) struct PacketMath {
    pub header: Header,
    pub id: Hash,
    pub transactions: Hash,
    pub digest: Hash,
}
struct PacketInput {
    bytes: Box<[u8]>,
    math: PacketMath,
}
struct DeltaLeaf {
    row: Delta,
    hash: Hash,
}
struct DeltaInput {
    rows: Box<[DeltaLeaf]>,
}

#[derive(Clone, Copy, Default, Serialize)]
struct Counters {
    record_bytes_observed: u64,
    record_hits: u64,
    record_computations: u64,
    packet_bytes_observed: u64,
    packet_hits: u64,
    packet_computations: u64,
    delta_rows_observed: u64,
    delta_payload_bytes_observed: u64,
    delta_leaf_hits: u64,
    delta_leaf_computations: u64,
    execution_parent_active_candidates: u64,
    execution_parent_historical_candidates: u64,
    execution_parent_checked_apply: u64,
    execution_parent_rebuilt_tree: u64,
    execution_parent_full_root: u64,
}

#[derive(Default)]
pub(crate) struct HistoryArithmetic {
    records: Pool<RecordInput>,
    packets: Pool<PacketInput>,
    deltas: Pool<DeltaInput>,
    counters: Cell<Counters>,
    stages: Arc<StageAccounting>,
    sql_commits: Arc<SqlCommitAccounting>,
    legacy_reorg_observation: Cell<bool>,
}
impl HistoryArithmetic {
    pub(crate) fn enable_legacy_reorg_observation(&self) {
        self.legacy_reorg_observation.set(true);
    }
    pub(crate) fn legacy_reorg_observation_enabled(&self) -> bool {
        self.legacy_reorg_observation.get()
    }
    pub(crate) fn legacy_reorg_observation(&self) -> Value {
        let rows = match self.stages.rows.try_lock() {
            Ok(rows) => Some(*rows),
            Err(_) => {
                self.stages.failed.store(true, Ordering::Relaxed);
                None
            }
        };
        let failed = self.stages.failed.load(Ordering::Relaxed);
        let roles = rows.map(|rows| {
            [
                (HistoryStage::VerifyState, "staging_validation"),
                (HistoryStage::ReadActive, "active_tail_validation"),
            ]
            .into_iter()
            .map(|(stage, role)| {
                let totals = rows[stage as usize];
                let counter_saturated = [
                    totals.calls,
                    totals.wall_ns,
                    totals.cpu_known_calls,
                    totals.cpu_unknown_calls,
                    totals.cpu_ns,
                    totals.unwinding_calls,
                ]
                .contains(&u64::MAX);
                let entered = totals.calls > 0;
                let known = !failed && !counter_saturated;
                json!({
                    "role":role,
                    "collector_stage":STAGE_NAMES[stage as usize],
                    "totals":totals,
                    "complete_wall_ns":(known && entered).then_some(totals.wall_ns),
                    "complete_cpu_ns":(known && entered
                        && totals.cpu_unknown_calls == 0
                        && totals.cpu_known_calls == totals.calls).then_some(totals.cpu_ns),
                    "known_cpu_ns_subtotal":(known && totals.cpu_known_calls > 0)
                        .then_some(totals.cpu_ns),
                    "counter_saturated":counter_saturated,
                    "per_outcome_counts":null
                })
            })
            .collect::<Vec<_>>()
        });
        json!({
            "schema":"pon-native-legacy-reorg-observation-v1",
            "backend":"legacy",
            "enabled":self.legacy_reorg_observation.get(),
            "scope":"explicit owner-local cumulative diagnostics; fresh staging validation and active-tail validation in original reorg transactions, including intent, detach/attach and publication; no State, SQL or validation result is reused",
            "roles":roles,
            "stage_observation_failed":failed,
            "stage_outcomes":"calls include ordinary errors, cancellation and unwind; there are no per-role success, failure or cancellation counters",
            "cpu_scope":"calling thread only; unknown or unentered complete CPU remains null; known subtotal is not complete CPU",
            "counter_scope":"raw zero counters mean unentered; saturated or failed measurements are unavailable; compare only the same owner's monotone snapshots without reset",
            "interval_scope":"component intervals are not complete importer time; nested observations are not generally additive",
            "sql_commit":self.sql_commits.legacy_reorg_observation(),
            "has_consensus_authority":false
        })
    }
    fn count(&self, action: impl FnOnce(&mut Counters)) {
        let mut counters = self.counters.get();
        action(&mut counters);
        self.counters.set(counters);
    }
    pub(crate) fn parent_binding(
        &self,
        active: bool,
        historical: bool,
        method: trnm_mvcc_fee::pon_commitment::CommitmentMethod,
    ) {
        // Successful complete actual-state bindings only; a selected candidate
        // is arithmetic, never an admission or retained SQL validity verdict.
        self.stages.parent_binding(active, historical, method);
    }
    pub(super) fn record(&self, settings: &Settings, block: Hash, bytes: &[u8]) -> Option<Record> {
        self.count(|c| {
            c.record_bytes_observed = c.record_bytes_observed.saturating_add(bytes.len() as u64)
        });
        let entry = self.records.get(Key::new(settings, block));
        if let Some(entry) = entry.filter(|entry| entry.value.bytes.as_ref() == bytes) {
            self.count(|c| c.record_hits = c.record_hits.saturating_add(1));
            return Some(entry.value.record.clone());
        }
        self.count(|c| c.record_computations = c.record_computations.saturating_add(1));
        None
    }
    pub(super) fn retain_record(
        &self,
        settings: &Settings,
        block: Hash,
        bytes: Vec<u8>,
        record: &Record,
    ) {
        let key = Key::new(settings, block);
        if !self.records.can_retain(key) {
            return;
        }
        let record = record.clone();
        let Some(charge) = bytes
            .len()
            .checked_add(record.schema.capacity())
            .and_then(|n| n.checked_add(record.state.schema.capacity()))
        else {
            return;
        };
        self.records.retain(
            key,
            RecordInput {
                bytes: bytes.into_boxed_slice(),
                record,
            },
            charge,
        );
    }
    pub(super) fn packet(
        &self,
        settings: &Settings,
        block: Hash,
        bytes: &[u8],
    ) -> Option<PacketMath> {
        self.count(|c| {
            c.packet_bytes_observed = c.packet_bytes_observed.saturating_add(bytes.len() as u64)
        });
        let entry = self.packets.get(Key::new(settings, block));
        if let Some(entry) = entry.filter(|entry| entry.value.bytes.as_ref() == bytes) {
            self.count(|c| c.packet_hits = c.packet_hits.saturating_add(1));
            return Some(entry.value.math.clone());
        }
        self.count(|c| c.packet_computations = c.packet_computations.saturating_add(1));
        None
    }
    pub(super) fn retain_packet(
        &self,
        settings: &Settings,
        block: Hash,
        bytes: Vec<u8>,
        math: PacketMath,
    ) {
        let key = Key::new(settings, block);
        if self.packets.can_retain(key) {
            let charge = bytes.len();
            self.packets.retain(
                key,
                PacketInput {
                    bytes: bytes.into_boxed_slice(),
                    math,
                },
                charge,
            );
        }
    }
    pub(super) fn delta_pass(&self, settings: &Settings, block: Hash) -> DeltaPass<'_> {
        let key = Key::new(settings, block);
        let candidate = self.deltas.get(key);
        let capture = self.deltas.can_retain(key).then(Vec::new);
        DeltaPass {
            cache: self,
            key,
            candidate,
            capture,
            payload: 0,
            index: 0,
        }
    }
    pub(crate) fn observe(&self, stage: HistoryStage) -> StageObservation {
        StageObservation {
            accounting: self.stages.clone(),
            stage,
            started: Instant::now(),
            thread: thread::current().id(),
            cpu: cpu_ns(),
        }
    }
    pub(crate) fn observe_sql_commit(&self, site: SqlCommitSite) -> SqlCommitObservation {
        SqlCommitObservation::start(self.sql_commits.clone(), site)
    }
    pub(crate) fn observation(&self) -> Value {
        let mut counters = self.counters.get();
        let bindings = &self.stages.parent_bindings;
        counters.execution_parent_active_candidates = bindings[0].load(Ordering::Relaxed);
        counters.execution_parent_historical_candidates = bindings[1].load(Ordering::Relaxed);
        counters.execution_parent_checked_apply = bindings[2].load(Ordering::Relaxed);
        counters.execution_parent_rebuilt_tree = bindings[3].load(Ordering::Relaxed);
        counters.execution_parent_full_root = bindings[4].load(Ordering::Relaxed);
        let stages = self.stages.rows.try_lock().ok().map(|rows| {
            rows.iter()
                .copied()
                .enumerate()
                .map(|(index, totals)| json!({"stage":STAGE_NAMES[index],"totals":totals}))
                .collect::<Vec<_>>()
        });
        json!({"schema":"pon-native-history-arithmetic-observation-v1",
            "scope":"cumulative actual native owner observations; nested intervals are not additive; current-thread CPU excludes scoped workers; errors and cancelled calls are included; unknown CPU is counted separately",
            "history_sql_traversal":"complete-original-O(H)-and-actual-delta-bytes",
            "cache_policy":"immutable-first-bounded-material-no-live-eviction",
            "retained_software_charge_limit_bytes":3*MAX_POOL_CHARGE,
            "charge_is_process_rss_bound":false,"has_consensus_authority":false,
            "records":self.records.status(),"packets":self.packets.status(),"deltas":self.deltas.status(),
            "counters":counters,"stage_observation_failed":self.stages.failed.load(Ordering::Relaxed),"stages":stages,
            "sql_commit":self.sql_commits.observation()})
    }
    #[cfg(test)]
    pub(super) fn clear(&self) {
        self.records.clear();
        self.packets.clear();
        self.deltas.clear();
    }
}

pub(super) struct DeltaPass<'a> {
    cache: &'a HistoryArithmetic,
    key: Key,
    // An immutable Arc is held, never a RefCell borrow across caller progress.
    candidate: Option<Arc<Entry<DeltaInput>>>,
    capture: Option<Vec<DeltaLeaf>>,
    payload: usize,
    index: usize,
}
impl DeltaPass<'_> {
    pub(super) fn leaf(&self, row: &Delta) -> Option<Hash> {
        let bytes =
            row.0.len() + row.1.as_ref().map_or(0, Vec::len) + row.2.as_ref().map_or(0, Vec::len);
        self.cache.count(|c| {
            c.delta_rows_observed = c.delta_rows_observed.saturating_add(1);
            c.delta_payload_bytes_observed =
                c.delta_payload_bytes_observed.saturating_add(bytes as u64);
        });
        let leaf = self
            .candidate
            .as_ref()
            .and_then(|entry| entry.value.rows.get(self.index))
            .filter(|leaf| &leaf.row == row)
            .map(|leaf| leaf.hash);
        self.cache.count(|c| {
            if leaf.is_some() {
                c.delta_leaf_hits = c.delta_leaf_hits.saturating_add(1);
            } else {
                c.delta_leaf_computations = c.delta_leaf_computations.saturating_add(1);
            }
        });
        leaf
    }
    pub(super) fn retain(&mut self, row: Delta, hash: Hash) {
        self.index += 1;
        let Some(rows) = self.capture.as_mut() else {
            return;
        };
        let next_capacity = if rows.len() == rows.capacity() {
            rows.capacity().max(2).saturating_mul(2)
        } else {
            rows.capacity()
        };
        let next_payload = self
            .payload
            .checked_add(row.0.capacity())
            .and_then(|n| n.checked_add(row.1.as_ref().map_or(0, Vec::capacity)))
            .and_then(|n| n.checked_add(row.2.as_ref().map_or(0, Vec::capacity)));
        let charge = next_capacity
            .checked_mul(size_of::<DeltaLeaf>())
            .and_then(|n| n.checked_add(ENTRY_OVERHEAD + size_of::<Entry<DeltaInput>>()))
            .and_then(|n| n.checked_add(next_payload?));
        if charge.is_none_or(|n| n > MAX_POOL_CHARGE) {
            self.capture = None;
            return;
        }
        if rows.len() == rows.capacity() {
            rows.reserve_exact(next_capacity - rows.len());
        }
        self.payload = next_payload.unwrap();
        rows.push(DeltaLeaf { row, hash });
    }
    pub(super) fn finish(self) {
        if let Some(rows) = self.capture {
            let Some(charge) = rows
                .len()
                .checked_mul(size_of::<DeltaLeaf>())
                .and_then(|n| n.checked_add(self.payload))
            else {
                return;
            };
            self.cache.deltas.retain(
                self.key,
                DeltaInput {
                    rows: rows.into_boxed_slice(),
                },
                charge,
            );
        }
    }
}

// Separate observation for the existing Transaction::commit API call only.
// Keep the original sixteen nested stage totals and their schema unchanged.
const SQL_COMMIT_SITES: [&str; 4] = [
    "admission_persistence",
    "atomic",
    "reorg_step",
    "reorg_termination",
];
#[derive(Clone, Copy)]
pub(crate) enum SqlCommitSite {
    AdmissionPersistence,
    Atomic,
    ReorgStep,
    ReorgTermination,
}
#[derive(Clone, Copy, Default, Serialize)]
struct SqlCommitTotals {
    calls_started: u64,
    calls_returned: u64,
    calls_succeeded: u64,
    calls_failed: u64,
    calls_abandoned: u64,
    calls_unwinding: u64,
    wall_ns: Option<u64>,
    cpu_ns: Option<u64>,
    cpu_ns_known_sum: u64,
    wall_unknown_calls: u64,
    cpu_known_calls: u64,
    cpu_unknown_calls: u64,
}
#[derive(Default)]
struct SqlCommitAccounting {
    rows: Mutex<[SqlCommitTotals; 4]>,
    failed: AtomicBool,
}
impl SqlCommitAccounting {
    fn legacy_reorg_observation(&self) -> Value {
        let mut value = self.observation();
        value["schema"] = json!("pon-native-legacy-reorg-sql-commit-call-observation-v1");
        value["scope"] = json!("explicitly enabled Legacy owner only; actual Transaction::commit API intervals at reorg_step and reorg_termination; reorg_step includes intent, detach/attach and final publication; admission_persistence and atomic are not enabled by this mode; errors may include existing rollback-on-drop; not isolated SQL statement time or physical fsync");
        value
    }
    fn fail(&self) {
        self.failed.store(true, Ordering::Relaxed);
    }
    fn add(&self, total: &mut u64, increment: u64) {
        match total.checked_add(increment) {
            Some(next) => *total = next,
            None => {
                *total = u64::MAX;
                self.fail();
            }
        }
    }
    fn sum(&self, previous: Option<u64>, sample: Option<u64>, first: bool) -> Option<u64> {
        if first {
            return sample;
        }
        let (previous, sample) = previous.zip(sample)?;
        let total = previous.checked_add(sample);
        if total.is_none() {
            self.fail();
        }
        total
    }
    fn observation(&self) -> Value {
        let rows = match self.rows.try_lock() {
            Ok(rows) => Some(*rows),
            Err(_) => {
                self.fail();
                None
            }
        };
        let sites = rows.map(|rows| {
            rows.into_iter()
                .enumerate()
                .map(|(index, totals)| {
                    let in_flight = totals
                        .calls_started
                        .checked_sub(totals.calls_returned)
                        .and_then(|n| n.checked_sub(totals.calls_abandoned));
                    json!({"site":SQL_COMMIT_SITES[index],"totals":totals,"calls_in_flight":in_flight})
                })
                .collect::<Vec<_>>()
        });
        json!({
            "schema":"pon-native-sql-commit-call-observation-v1",
            "scope":"authenticated backend only; actual Transaction::commit API intervals at admission, shared atomic, reorg-step and reorg-termination sites; errors may include the API's existing rollback-on-drop; not isolated SQL statement time or physical fsync; initial seeding and peer replay commits are outside these four sites",
            "pre_commit_refusals":"remain in the original caller outcomes; zero entered SQL calls does not count or classify cancellations",
            "cpu_scope":"calling thread only; unknown or unentered complete CPU remains null; known subtotal is not complete CPU",
            "observation_failed":self.failed.load(Ordering::Relaxed),
            "has_consensus_authority":false,
            "sites":sites
        })
    }
}
pub(crate) struct SqlCommitObservation {
    accounting: Arc<SqlCommitAccounting>,
    site: SqlCommitSite,
    started: Instant,
    thread: ThreadId,
    cpu: Option<u64>,
    recorded: bool,
    returned: Option<bool>,
}
impl SqlCommitObservation {
    fn start(accounting: Arc<SqlCommitAccounting>, site: SqlCommitSite) -> Self {
        let recorded = match accounting.rows.try_lock() {
            Ok(mut rows) => {
                let row = &mut rows[site as usize];
                match row.calls_started.checked_add(1) {
                    Some(next) => {
                        row.calls_started = next;
                        true
                    }
                    None => {
                        accounting.fail();
                        false
                    }
                }
            }
            Err(_) => {
                accounting.fail();
                false
            }
        };
        Self {
            accounting,
            site,
            started: Instant::now(),
            thread: thread::current().id(),
            cpu: cpu_ns(),
            recorded,
            returned: None,
        }
    }
    pub(crate) fn finish_sql_result(mut self, result: &rusqlite::Result<()>) {
        self.returned = Some(result.is_ok());
    }
}
impl Drop for SqlCommitObservation {
    fn drop(&mut self) {
        if !self.recorded {
            return;
        }
        let ended = Instant::now();
        let wall = ended
            .checked_duration_since(self.started)
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok());
        let cpu = (self.thread == thread::current().id())
            .then(cpu_ns)
            .flatten()
            .zip(self.cpu)
            .and_then(|(end, start)| end.checked_sub(start));
        let Ok(mut rows) = self.accounting.rows.try_lock() else {
            self.accounting.fail();
            return;
        };
        let row = &mut rows[self.site as usize];
        let first = row.calls_returned == 0 && row.calls_abandoned == 0;
        row.wall_ns = self.accounting.sum(row.wall_ns, wall, first);
        row.cpu_ns = self.accounting.sum(row.cpu_ns, cpu, first);
        self.accounting
            .add(&mut row.wall_unknown_calls, u64::from(wall.is_none()));
        if let Some(cpu) = cpu {
            self.accounting.add(&mut row.cpu_known_calls, 1);
            self.accounting.add(&mut row.cpu_ns_known_sum, cpu);
        } else {
            self.accounting.add(&mut row.cpu_unknown_calls, 1);
        }
        if let Some(success) = self.returned {
            self.accounting.add(&mut row.calls_returned, 1);
            if success {
                self.accounting.add(&mut row.calls_succeeded, 1);
            } else {
                self.accounting.add(&mut row.calls_failed, 1);
            }
        } else {
            self.accounting.add(&mut row.calls_abandoned, 1);
        }
        self.accounting
            .add(&mut row.calls_unwinding, u64::from(thread::panicking()));
    }
}

const STAGES: usize = 16;
const STAGE_NAMES: [&str; STAGES] = [
    "record",
    "packet",
    "delta",
    "verify_state",
    "verify_history",
    "publish",
    "read_active",
    "state_at",
    "execute",
    "admission",
    "activation",
    "complete_commitment",
    "complete_state_root",
    "account_graph",
    "persisted_state_root",
    "execution_parent_binding",
];
#[derive(Clone, Copy)]
pub(crate) enum HistoryStage {
    Record,
    Packet,
    Delta,
    VerifyState,
    VerifyHistory,
    Publish,
    ReadActive,
    StateAt,
    Execute,
    Admission,
    Activation,
    CompleteCommitment,
    CompleteStateRoot,
    AccountGraph,
    PersistedStateRoot,
    ExecutionParentBinding,
}
#[derive(Clone, Copy, Default, Serialize)]
struct StageTotals {
    calls: u64,
    wall_ns: u64,
    cpu_known_calls: u64,
    cpu_unknown_calls: u64,
    cpu_ns: u64,
    unwinding_calls: u64,
}
#[derive(Default)]
struct StageAccounting {
    rows: Mutex<[StageTotals; STAGES]>,
    failed: AtomicBool,
    parent_bindings: [AtomicU64; 5],
}
impl StageAccounting {
    fn parent_binding(
        &self,
        active: bool,
        historical: bool,
        method: trnm_mvcc_fee::pon_commitment::CommitmentMethod,
    ) {
        use trnm_mvcc_fee::pon_commitment::CommitmentMethod;
        let method = match method {
            CommitmentMethod::CheckedApply => 2,
            CommitmentMethod::RebuiltTree => 3,
            CommitmentMethod::FullRoot(_) => 4,
        };
        for (index, count) in [
            (0, u64::from(active)),
            (1, u64::from(historical)),
            (method, 1),
        ] {
            let _ = self.parent_bindings[index].fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |prior| Some(prior.saturating_add(count)),
            );
        }
    }
}
pub(crate) struct StageObservation {
    accounting: Arc<StageAccounting>,
    stage: HistoryStage,
    started: Instant,
    thread: ThreadId,
    cpu: Option<u64>,
}
impl StageObservation {
    pub(crate) fn parent_binding(
        &self,
        active: bool,
        historical: bool,
        method: trnm_mvcc_fee::pon_commitment::CommitmentMethod,
    ) {
        self.accounting.parent_binding(active, historical, method);
    }
}
impl Drop for StageObservation {
    fn drop(&mut self) {
        let cpu = (self.thread == thread::current().id())
            .then(cpu_ns)
            .flatten()
            .zip(self.cpu)
            .and_then(|(end, start)| end.checked_sub(start));
        let Ok(mut stages) = self.accounting.rows.try_lock() else {
            self.accounting.failed.store(true, Ordering::Relaxed);
            return;
        };
        let row = &mut stages[self.stage as usize];
        row.calls = row.calls.saturating_add(1);
        row.wall_ns = row
            .wall_ns
            .saturating_add(u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX));
        if let Some(cpu) = cpu {
            row.cpu_known_calls = row.cpu_known_calls.saturating_add(1);
            row.cpu_ns = row.cpu_ns.saturating_add(cpu);
        } else {
            row.cpu_unknown_calls = row.cpu_unknown_calls.saturating_add(1);
        }
        row.unwinding_calls = row
            .unwinding_calls
            .saturating_add(u64::from(thread::panicking()));
    }
}
#[cfg(target_os = "linux")]
fn cpu_ns() -> Option<u64> {
    use rustix::time::{clock_gettime_dynamic, ClockId, DynamicClockId};
    let stamp = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
    let sec = u64::try_from(stamp.tv_sec).ok()?;
    let nanos = u64::try_from(stamp.tv_nsec).ok()?;
    (nanos < 1_000_000_000).then_some(())?;
    sec.checked_mul(1_000_000_000)?.checked_add(nanos)
}
#[cfg(not(target_os = "linux"))]
fn cpu_ns() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests;
