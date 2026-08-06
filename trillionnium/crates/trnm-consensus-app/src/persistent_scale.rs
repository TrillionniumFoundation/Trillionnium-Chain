//! Persistent SQLite AppHash v4 scale gate.
//!
//! The existing in-memory scale gate isolates JMT algorithmic growth. This
//! gate deliberately exercises the production SQLite planning and FULL-sync
//! persistence path, durable budgeted pruning, proofs, and process-style
//! reopen validation. It remains feature-gated so benchmark-only construction
//! helpers are absent from production nodes.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use tendermint_abci::Application;
use tendermint_proto::{
    google::protobuf::Timestamp,
    v0_38::{
        abci::{
            response_apply_snapshot_chunk, response_offer_snapshot, RequestApplySnapshotChunk,
            RequestFinalizeBlock, RequestInitChain, RequestLoadSnapshotChunk, RequestOfferSnapshot,
            Snapshot,
        },
        types::{ConsensusParams, VersionParams},
    },
};
use trnm_node::live::{
    node::AuthorizedSignerV1,
    store::{ObjectMutation, StoredObject},
};
use trnm_research_protocol::AuthoritySetV1;

use crate::{
    auth_tree::stored_object_key,
    authenticated_writes_for_delta, build_store_snapshot, install_snapshot_record,
    store::ApplicationStore,
    validator_lifecycle::{
        validators_to_abci, ConsensusValidatorV1, ValidatorGovernanceV1,
        VALIDATOR_GOVERNANCE_SCHEMA_V1,
    },
    AppState, BlockDelta, CometBftApplication, ConsensusAppConfig, GenesisAppStateV3, PendingBlock,
    PendingDiskSnapshot, APP_VERSION, CONFIG_SCHEMA_V1, GENESIS_SCHEMA_V3, RETAINED_DISK_SNAPSHOTS,
    SNAPSHOT_FORMAT_V4,
};

const REPORT_SCHEMA_V1: &str = "trnm_apphash_v4_persistent_scale_report_v1";
const SCALE_OBJECT_TYPE: &str = "trnm_persistent_scale_object_v1";
const SCALE_CHAIN_ID: &str = "trnm-persistent-scale-gate";
const SCALE_SIGNER_ID: &str = "did:operator:persistent-scale";
const MILLION: u64 = 1_000_000;
const PRUNE_CONCURRENT_COMMITS: u64 = 32;
const PRUNE_PINNED_COMMITS: u64 = 4;

#[derive(Clone, Debug)]
pub struct PersistentScaleConfig {
    pub work_dir: PathBuf,
    pub objects: u64,
    pub updates: u64,
    pub batch_size: u64,
    pub live_set: u64,
    pub prune_retain_versions: u64,
    pub prune_batch_rows: usize,
    pub prune_batch_logical_bytes: u64,
}

impl Default for PersistentScaleConfig {
    fn default() -> Self {
        Self {
            work_dir: PathBuf::from("trnm-persistent-scale-data"),
            objects: MILLION,
            updates: MILLION,
            batch_size: 10_000,
            live_set: 10_000,
            prune_retain_versions: 64,
            prune_batch_rows: 256,
            prune_batch_logical_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistentScaleScope {
    pub persistent_sqlite: bool,
    pub sqlite_synchronous_full: bool,
    pub single_process: bool,
    pub single_host: bool,
    pub cometbft_end_to_end: bool,
    pub public_testnet_evidence: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistentScaleParameters {
    pub work_dir: String,
    pub objects: u64,
    pub updates: u64,
    pub batch_size: u64,
    pub fixed_live_set: u64,
    pub prune_retain_versions: u64,
    pub prune_batch_rows: usize,
    pub prune_batch_logical_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PersistentScaleCompleted {
    pub objects: u64,
    pub updates: u64,
    pub initial_load_batches: u64,
    pub update_batches: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistentScalePhase {
    InitialLoad,
    Update,
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistentBatchMetric {
    pub phase: PersistentScalePhase,
    pub batch_index: u64,
    pub version: u64,
    pub operations: u64,
    pub phase_operations_completed: u64,
    pub plan_us: u64,
    pub persist_us: u64,
    pub total_us: u64,
    pub root_hash_hex: String,
    pub database_logical_bytes: u64,
    pub wal_logical_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistentLatencyStats {
    pub samples: u64,
    pub min_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PhaseLatencyReport {
    pub phase: PersistentScalePhase,
    pub plan: PersistentLatencyStats,
    pub persist: PersistentLatencyStats,
    pub total: PersistentLatencyStats,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct FileUsage {
    pub exists: bool,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PersistentFilePeaks {
    pub database_logical_bytes: u64,
    pub database_allocated_bytes: u64,
    pub wal_logical_bytes: u64,
    pub wal_allocated_bytes: u64,
    pub shm_logical_bytes: u64,
    pub shm_allocated_bytes: u64,
    pub snapshot_logical_bytes: u64,
    pub snapshot_allocated_bytes: u64,
    pub restore_staging_logical_bytes: u64,
    pub restore_staging_allocated_bytes: u64,
    pub temporary_logical_bytes: u64,
    pub temporary_allocated_bytes: u64,
    pub work_dir_logical_bytes: u64,
    pub work_dir_allocated_bytes: u64,
}

impl PersistentFilePeaks {
    fn merge(&mut self, other: &Self) {
        self.database_logical_bytes = self
            .database_logical_bytes
            .max(other.database_logical_bytes);
        self.database_allocated_bytes = self
            .database_allocated_bytes
            .max(other.database_allocated_bytes);
        self.wal_logical_bytes = self.wal_logical_bytes.max(other.wal_logical_bytes);
        self.wal_allocated_bytes = self.wal_allocated_bytes.max(other.wal_allocated_bytes);
        self.shm_logical_bytes = self.shm_logical_bytes.max(other.shm_logical_bytes);
        self.shm_allocated_bytes = self.shm_allocated_bytes.max(other.shm_allocated_bytes);
        self.snapshot_logical_bytes = self
            .snapshot_logical_bytes
            .max(other.snapshot_logical_bytes);
        self.snapshot_allocated_bytes = self
            .snapshot_allocated_bytes
            .max(other.snapshot_allocated_bytes);
        self.restore_staging_logical_bytes = self
            .restore_staging_logical_bytes
            .max(other.restore_staging_logical_bytes);
        self.restore_staging_allocated_bytes = self
            .restore_staging_allocated_bytes
            .max(other.restore_staging_allocated_bytes);
        self.temporary_logical_bytes = self
            .temporary_logical_bytes
            .max(other.temporary_logical_bytes);
        self.temporary_allocated_bytes = self
            .temporary_allocated_bytes
            .max(other.temporary_allocated_bytes);
        self.work_dir_logical_bytes = self
            .work_dir_logical_bytes
            .max(other.work_dir_logical_bytes);
        self.work_dir_allocated_bytes = self
            .work_dir_allocated_bytes
            .max(other.work_dir_allocated_bytes);
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DatabaseMetrics {
    pub stage: String,
    pub journal_mode: String,
    pub synchronous: i64,
    pub page_size: u64,
    pub page_count: u64,
    pub freelist_count: u64,
    pub objects: u64,
    pub auth_nodes: u64,
    pub auth_values: u64,
    pub auth_preimages: u64,
    pub auth_stale_nodes: u64,
    pub auth_stale_values: u64,
    pub auth_roots: u64,
    pub database: FileUsage,
    pub wal: FileUsage,
    pub shm: FileUsage,
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistentProofMetric {
    pub stage: String,
    pub version: u64,
    pub key_hex: String,
    pub membership: bool,
    pub value_bytes: u64,
    pub proof_bytes: u64,
    pub root_hash_hex: String,
    pub elapsed_us: u64,
    pub verified_by_store: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PersistentPruneRemovals {
    pub nodes: u64,
    pub value_versions: u64,
    pub key_preimages: u64,
    pub stale_indices: u64,
    pub roots: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistentPruneReport {
    pub collision_requested_floor: u64,
    pub requested_floor: u64,
    pub query_floor_after_request: u64,
    pub target_after_request: Option<u64>,
    pub batches: u64,
    pub writer_busy_yields: u64,
    pub snapshot_pin_yield_observed: bool,
    pub concurrent_commits: u64,
    pub concurrent_commit_latency: PersistentLatencyStats,
    pub rows_examined: u64,
    pub logical_bytes_examined: u64,
    pub removals: PersistentPruneRemovals,
    pub batch_latency: PersistentLatencyStats,
    pub elapsed_us: u64,
    pub final_query_floor: u64,
    pub final_target: Option<u64>,
    pub complete: bool,
    pub floor_minus_one_rejected: Option<bool>,
    pub latest_root_unchanged: bool,
}

struct PruneDrainResult {
    batches: u64,
    rows_examined: u64,
    logical_bytes_examined: u64,
    removals: PersistentPruneRemovals,
    latencies: Vec<u64>,
}

impl PruneDrainResult {
    fn merge(&mut self, other: Self) {
        self.batches = self.batches.saturating_add(other.batches);
        self.rows_examined = self.rows_examined.saturating_add(other.rows_examined);
        self.logical_bytes_examined = self
            .logical_bytes_examined
            .saturating_add(other.logical_bytes_examined);
        self.removals.nodes = self.removals.nodes.saturating_add(other.removals.nodes);
        self.removals.value_versions = self
            .removals
            .value_versions
            .saturating_add(other.removals.value_versions);
        self.removals.key_preimages = self
            .removals
            .key_preimages
            .saturating_add(other.removals.key_preimages);
        self.removals.stale_indices = self
            .removals
            .stale_indices
            .saturating_add(other.removals.stale_indices);
        self.removals.roots = self.removals.roots.saturating_add(other.removals.roots);
        self.latencies.extend(other.latencies);
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistentRestartReport {
    pub elapsed_us: u64,
    pub height: u64,
    pub app_hash_hex: String,
    pub expected_height: u64,
    pub expected_app_hash_hex: String,
    pub exact_head_match: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistentSnapshotReport {
    pub format: u32,
    pub chunks: u32,
    pub total_bytes: u64,
    pub build_us: u64,
    pub restore_us: u64,
    pub resumed_across_restart: bool,
    pub chunks_before_restart: u32,
    pub source_height: u64,
    pub source_app_hash_hex: String,
    pub restored_height: u64,
    pub restored_app_hash_hex: String,
    pub exact_head_match: bool,
    pub continued_height: u64,
    pub continued_app_hash_hex: String,
    pub continued_after_restore: bool,
    pub restart_after_continue_us: u64,
    pub restart_after_continue_match: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PersistentScaleReport {
    pub schema: &'static str,
    pub workload_class: &'static str,
    pub measurement_profile: &'static str,
    pub million_gate_eligible: bool,
    pub scope: PersistentScaleScope,
    pub parameters: PersistentScaleParameters,
    pub completed: PersistentScaleCompleted,
    pub completed_exactly: bool,
    pub batch_metrics: Vec<PersistentBatchMetric>,
    pub phase_latency: Vec<PhaseLatencyReport>,
    pub prune: Option<PersistentPruneReport>,
    pub proofs: Vec<PersistentProofMetric>,
    pub restart: Option<PersistentRestartReport>,
    pub snapshot: Option<PersistentSnapshotReport>,
    pub database_metrics: Vec<DatabaseMetrics>,
    pub file_peaks: PersistentFilePeaks,
    pub elapsed_us: u64,
    pub passed: bool,
    pub failure_reason: Option<String>,
}

impl PersistentScaleReport {
    fn new(config: &PersistentScaleConfig) -> Self {
        let at_least_million = config.objects >= MILLION && config.updates >= MILLION;
        Self {
            schema: REPORT_SCHEMA_V1,
            workload_class: if at_least_million {
                "at_least_1m_objects_and_1m_updates"
            } else {
                "smoke_or_custom_below_1m_not_a_million_gate"
            },
            measurement_profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            million_gate_eligible: at_least_million && !cfg!(debug_assertions),
            scope: PersistentScaleScope {
                persistent_sqlite: true,
                sqlite_synchronous_full: true,
                single_process: true,
                single_host: true,
                cometbft_end_to_end: false,
                public_testnet_evidence: false,
            },
            parameters: PersistentScaleParameters {
                work_dir: config.work_dir.display().to_string(),
                objects: config.objects,
                updates: config.updates,
                batch_size: config.batch_size,
                fixed_live_set: config.live_set,
                prune_retain_versions: config.prune_retain_versions,
                prune_batch_rows: config.prune_batch_rows,
                prune_batch_logical_bytes: config.prune_batch_logical_bytes,
            },
            completed: PersistentScaleCompleted::default(),
            completed_exactly: false,
            batch_metrics: Vec::new(),
            phase_latency: Vec::new(),
            prune: None,
            proofs: Vec::new(),
            restart: None,
            snapshot: None,
            database_metrics: Vec::new(),
            file_peaks: PersistentFilePeaks::default(),
            elapsed_us: 0,
            passed: false,
            failure_reason: None,
        }
    }
}

struct DiskPeakSampler {
    stop: Arc<AtomicBool>,
    peaks: Arc<Mutex<PersistentFilePeaks>>,
    error: Arc<Mutex<Option<String>>>,
    handle: Option<JoinHandle<()>>,
}

impl DiskPeakSampler {
    fn start(root: PathBuf) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let peaks = Arc::new(Mutex::new(PersistentFilePeaks::default()));
        let error = Arc::new(Mutex::new(None));
        let thread_stop = Arc::clone(&stop);
        let thread_peaks = Arc::clone(&peaks);
        let thread_error = Arc::clone(&error);
        let handle = std::thread::Builder::new()
            .name("trnm-persistent-disk-sampler".to_string())
            .spawn(move || loop {
                match sample_work_dir_peaks(&root) {
                    Ok(sample) => match thread_peaks.lock() {
                        Ok(mut peaks) => peaks.merge(&sample),
                        Err(_) => {
                            if let Ok(mut error) = thread_error.lock() {
                                *error = Some("persistent disk peak lock poisoned".to_string());
                            }
                            return;
                        }
                    },
                    Err(sample_error) => {
                        if let Ok(mut error) = thread_error.lock() {
                            *error = Some(format!("{sample_error:#}"));
                        }
                        return;
                    }
                }
                if thread_stop.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            })
            .context("spawn persistent disk peak sampler")?;
        Ok(Self {
            stop,
            peaks,
            error,
            handle: Some(handle),
        })
    }

    fn finish(mut self) -> Result<PersistentFilePeaks> {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("persistent disk peak sampler panicked"))?;
        }
        if let Some(error) = self
            .error
            .lock()
            .map_err(|_| anyhow::anyhow!("persistent disk sampler error lock poisoned"))?
            .clone()
        {
            anyhow::bail!("persistent disk peak sampler failed: {error}");
        }
        let peaks = self
            .peaks
            .lock()
            .map_err(|_| anyhow::anyhow!("persistent disk peak lock poisoned"))?
            .clone();
        Ok(peaks)
    }
}

impl Drop for DiskPeakSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Runs the persistent scale workload and always returns a serializable report.
///
/// The work directory must either not exist or be empty. Existing evidence is
/// never deleted or overwritten by the library.
pub fn run_persistent_scale_gate(config: PersistentScaleConfig) -> PersistentScaleReport {
    let started = Instant::now();
    let mut report = PersistentScaleReport::new(&config);
    if let Err(error) = execute_persistent_scale_gate(&config, &mut report) {
        report.failure_reason = Some(format!("{error:#}"));
    }
    report.completed_exactly =
        report.completed.objects == config.objects && report.completed.updates == config.updates;
    report.phase_latency = phase_latency_reports(&report.batch_metrics);
    if report.failure_reason.is_none() && !report.completed_exactly {
        report.failure_reason =
            Some("requested persistent workload was not completed exactly".to_string());
    }
    if report.failure_reason.is_none()
        && !report.prune.as_ref().is_some_and(|prune| {
            prune.complete
                && prune.latest_root_unchanged
                && prune.snapshot_pin_yield_observed
                && prune.concurrent_commits == PRUNE_CONCURRENT_COMMITS
                && prune.concurrent_commit_latency.samples == PRUNE_CONCURRENT_COMMITS
                && prune.query_floor_after_request == prune.requested_floor
                && prune.final_query_floor == prune.requested_floor
                && prune.target_after_request == Some(prune.requested_floor)
                && prune.final_target.is_none()
                && prune.floor_minus_one_rejected == Some(true)
                && prune.removals.nodes > 0
                && prune.removals.value_versions > 0
                && prune.removals.stale_indices > 0
                && prune.removals.roots > 0
        })
    {
        report.failure_reason = Some(
            "durable authenticated pruning did not close its final retention floor safely"
                .to_string(),
        );
    }
    if report.failure_reason.is_none()
        && !report
            .restart
            .as_ref()
            .is_some_and(|restart| restart.exact_head_match)
    {
        report.failure_reason =
            Some("persistent reopen did not reproduce the exact head".to_string());
    }
    if report.failure_reason.is_none()
        && !report.snapshot.as_ref().is_some_and(|snapshot| {
            snapshot.format == SNAPSHOT_FORMAT_V4
                && snapshot.exact_head_match
                && snapshot.continued_after_restore
                && snapshot.restart_after_continue_match
                && if snapshot.chunks > 1 {
                    snapshot.resumed_across_restart
                        && snapshot.chunks_before_restart > 0
                        && snapshot.chunks_before_restart < snapshot.chunks
                } else {
                    !snapshot.resumed_across_restart && snapshot.chunks_before_restart == 0
                }
        })
    {
        report.failure_reason =
            Some("format-4 snapshot restore and continuation did not close".to_string());
    }
    if report.failure_reason.is_none()
        && !(report.file_peaks.database_logical_bytes > 0
            && report.file_peaks.snapshot_logical_bytes > 0
            && report.file_peaks.restore_staging_logical_bytes > 0
            && report.file_peaks.temporary_logical_bytes > 0
            && report.file_peaks.work_dir_logical_bytes > 0)
    {
        report.failure_reason = Some(
            "persistent database, snapshot, restore, or temporary disk peaks are absent".into(),
        );
    }
    report.elapsed_us = elapsed_us(started);
    report.passed = report.failure_reason.is_none() && report.completed_exactly;
    report
}

fn execute_persistent_scale_gate(
    config: &PersistentScaleConfig,
    report: &mut PersistentScaleReport,
) -> Result<()> {
    validate_config(config)?;
    prepare_work_dir(&config.work_dir)?;
    let disk_sampler = DiskPeakSampler::start(config.work_dir.clone())?;

    let status_path = config.work_dir.join("source.status");
    let database_path = database_path_for_status(&status_path);
    let app_config = scale_application_config(status_path);
    let application = initialize_application(app_config.clone())?;
    let store = application
        .core
        .store
        .clone()
        .context("persistent scale application did not install a SQLite store")?;
    let mut state = application
        .core
        .state
        .lock()
        .map_err(|_| anyhow::anyhow!("persistent scale state lock poisoned"))?
        .clone();
    drop(application);

    sample_file_peaks(&database_path, &mut report.file_peaks)?;
    report
        .database_metrics
        .push(database_metrics("after_genesis", &database_path)?);

    while report.completed.objects < config.objects {
        let count = config
            .batch_size
            .min(config.objects - report.completed.objects);
        let start_index = report.completed.objects;
        let objects = (0..count)
            .map(|offset| {
                let object_index = start_index.saturating_add(offset);
                scale_object(object_index, 0, 1)
            })
            .collect::<Vec<_>>();
        let completed = report.completed.objects.saturating_add(count);
        let metric = persist_batch(
            &store,
            &mut state,
            PersistentScalePhase::InitialLoad,
            report.completed.initial_load_batches,
            completed,
            objects,
            &database_path,
        )?;
        report.batch_metrics.push(metric);
        report.completed.objects = completed;
        report.completed.initial_load_batches =
            report.completed.initial_load_batches.saturating_add(1);
        sample_file_peaks(&database_path, &mut report.file_peaks)?;
    }

    while report.completed.updates < config.updates {
        let count = config
            .batch_size
            .min(config.updates - report.completed.updates);
        let start_sequence = report.completed.updates;
        let objects = (0..count)
            .map(|offset| {
                let sequence = start_sequence.saturating_add(offset);
                let object_index = sequence % config.live_set;
                let object_version = (sequence / config.live_set).saturating_add(2);
                scale_object(object_index, sequence.saturating_add(1), object_version)
            })
            .collect::<Vec<_>>();
        let completed = report.completed.updates.saturating_add(count);
        let metric = persist_batch(
            &store,
            &mut state,
            PersistentScalePhase::Update,
            report.completed.update_batches,
            completed,
            objects,
            &database_path,
        )?;
        report.batch_metrics.push(metric);
        report.completed.updates = completed;
        report.completed.update_batches = report.completed.update_batches.saturating_add(1);
        sample_file_peaks(&database_path, &mut report.file_peaks)?;
    }

    report
        .database_metrics
        .push(database_metrics("before_prune", &database_path)?);

    let workload_latest = state.height;
    let collision_boundary =
        workload_latest.saturating_sub(config.prune_retain_versions.saturating_sub(1));
    let proof_key = stored_object_key(&scale_object_id(0))?;
    let missing_key = stored_object_key("persistent-scale-object-missing")?;
    report.proofs.push(measure_proof(
        &store,
        "before_collision_prune_boundary_membership",
        collision_boundary,
        proof_key.clone(),
        true,
    )?);
    report.proofs.push(measure_proof(
        &store,
        "before_prune_latest_membership",
        workload_latest,
        proof_key.clone(),
        true,
    )?);
    report.proofs.push(measure_proof(
        &store,
        "before_prune_latest_nonmembership",
        workload_latest,
        missing_key.clone(),
        false,
    )?);

    let latest_root_before = state.app_hash;
    let collision_request = store
        .request_auth_prune(collision_boundary)
        .context("request persistent collision prune floor")?;
    let prune_started = Instant::now();
    let pinned = store
        .pin_snapshot(&state)
        .context("pin persistent snapshot during authenticated pruning")?;
    let writer_busy_yields = Arc::new(AtomicU64::new(0));
    let drain_busy_yields = Arc::clone(&writer_busy_yields);
    let drain_store = store.clone();
    let prune_batch_rows = config.prune_batch_rows;
    let prune_batch_logical_bytes = config.prune_batch_logical_bytes;
    let drain = std::thread::Builder::new()
        .name("trnm-persistent-prune-drain".to_string())
        .spawn(move || {
            drain_persistent_prune(
                &drain_store,
                prune_batch_rows,
                prune_batch_logical_bytes,
                &drain_busy_yields,
            )
        })
        .context("spawn persistent prune drain")?;
    for _ in 0..1_000 {
        if writer_busy_yields.load(Ordering::Acquire) > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    ensure!(
        writer_busy_yields.load(Ordering::Acquire) > 0,
        "authenticated pruning did not yield to the pinned snapshot"
    );
    let mut pinned = Some(pinned);
    let mut concurrent_commit_latencies =
        Vec::with_capacity(usize::try_from(PRUNE_CONCURRENT_COMMITS)?);
    for index in 0..PRUNE_CONCURRENT_COMMITS {
        concurrent_commit_latencies.push(
            persist_empty_collision_version(&store, &mut state).with_context(|| {
                format!(
                    "persist prune-collision version {}",
                    state.height.saturating_add(1)
                )
            })?,
        );
        if index.saturating_add(1) == PRUNE_PINNED_COMMITS {
            drop(pinned.take());
        }
    }
    drop(pinned);
    let mut drained = drain
        .join()
        .map_err(|_| anyhow::anyhow!("persistent prune drain panicked"))?
        .context("drain persistent authenticated prune")?;
    let latest = state.height;
    ensure!(
        state.app_hash == latest_root_before,
        "empty prune-collision commits changed the authenticated state root"
    );
    let boundary = latest.saturating_sub(config.prune_retain_versions.saturating_sub(1));
    ensure!(
        boundary >= collision_boundary,
        "final authenticated prune floor moved backwards"
    );
    report.proofs.push(measure_proof(
        &store,
        "before_final_prune_boundary_membership",
        boundary,
        proof_key.clone(),
        true,
    )?);
    let request = store
        .request_auth_prune(boundary)
        .context("request final persistent authenticated prune floor")?;
    if request.target.is_some() {
        drained.merge(
            drain_persistent_prune(
                &store,
                config.prune_batch_rows,
                config.prune_batch_logical_bytes,
                &writer_busy_yields,
            )
            .context("drain final persistent authenticated prune")?,
        );
    }
    let writer_busy_yields = writer_busy_yields.load(Ordering::Acquire);
    let final_status = store.auth_prune_status()?;
    let floor_minus_one_rejected = boundary
        .checked_sub(1)
        .map(|version| store.prove(version, proof_key.clone()).is_err());
    let latest_after = measure_proof(
        &store,
        "after_prune_latest_membership",
        latest,
        proof_key.clone(),
        true,
    )?;
    let latest_root_after =
        trnm_finality_types::decode_hash32("latest proof root", &latest_after.root_hash_hex)?;
    report.proofs.push(measure_proof(
        &store,
        "after_prune_boundary_membership",
        boundary,
        proof_key,
        true,
    )?);
    report.proofs.push(latest_after);
    report.proofs.push(measure_proof(
        &store,
        "after_prune_latest_nonmembership",
        latest,
        missing_key,
        false,
    )?);
    let complete = final_status.query_floor == boundary && final_status.target.is_none();
    ensure!(
        complete,
        "durable authenticated prune target remains pending"
    );
    ensure!(
        floor_minus_one_rejected != Some(false),
        "version below the durable query floor remained queryable"
    );
    ensure!(
        latest_root_after == latest_root_before,
        "authenticated pruning changed the latest AppHash"
    );
    report.prune = Some(PersistentPruneReport {
        collision_requested_floor: collision_request.query_floor,
        requested_floor: boundary,
        query_floor_after_request: request.query_floor,
        target_after_request: request.target,
        batches: drained.batches,
        writer_busy_yields,
        snapshot_pin_yield_observed: writer_busy_yields > 0,
        concurrent_commits: PRUNE_CONCURRENT_COMMITS,
        concurrent_commit_latency: latency_stats(&concurrent_commit_latencies)?,
        rows_examined: drained.rows_examined,
        logical_bytes_examined: drained.logical_bytes_examined,
        removals: drained.removals,
        batch_latency: latency_stats(&drained.latencies)?,
        elapsed_us: elapsed_us(prune_started),
        final_query_floor: final_status.query_floor,
        final_target: final_status.target,
        complete,
        floor_minus_one_rejected,
        latest_root_unchanged: latest_root_after == latest_root_before,
    });
    report
        .database_metrics
        .push(database_metrics("after_prune", &database_path)?);

    drop(store);
    let restart_started = Instant::now();
    let restarted = CometBftApplication::new(app_config.clone())?;
    let restart_elapsed_us = elapsed_us(restart_started);
    let (restart_height, restart_hash) = restarted.height_and_app_hash()?;
    let exact_head_match = restart_height == latest && restart_hash == latest_root_before;
    ensure!(
        exact_head_match,
        "reopened persistent application head differs from the committed head"
    );
    let restarted_store = restarted
        .core
        .store
        .as_ref()
        .context("reopened persistent application has no SQLite store")?;
    report.proofs.push(measure_proof(
        restarted_store,
        "after_restart_latest_membership",
        latest,
        stored_object_key(&scale_object_id(0))?,
        true,
    )?);
    report.restart = Some(PersistentRestartReport {
        elapsed_us: restart_elapsed_us,
        height: restart_height,
        app_hash_hex: hex::encode(restart_hash),
        expected_height: latest,
        expected_app_hash_hex: hex::encode(latest_root_before),
        exact_head_match,
    });
    report
        .database_metrics
        .push(database_metrics("after_restart", &database_path)?);
    sample_file_peaks(&database_path, &mut report.file_peaks)?;
    let snapshot_report =
        exercise_format4_snapshot_restore(config, report, &restarted, latest, latest_root_before)?;
    report.snapshot = Some(snapshot_report);
    let sampled_peaks = disk_sampler.finish()?;
    report.file_peaks.merge(&sampled_peaks);
    Ok(())
}

fn drain_persistent_prune(
    store: &ApplicationStore,
    max_rows: usize,
    max_logical_bytes: u64,
    writer_busy_yields: &AtomicU64,
) -> Result<PruneDrainResult> {
    let mut result = PruneDrainResult {
        batches: 0,
        rows_examined: 0,
        logical_bytes_examined: 0,
        removals: PersistentPruneRemovals::default(),
        latencies: Vec::new(),
    };
    loop {
        let outcome = match store.try_prune_auth_batch(max_rows, max_logical_bytes) {
            Ok(outcome) => outcome,
            Err(error) if crate::is_transient_sqlite_contention(&error) => {
                writer_busy_yields.fetch_add(1, Ordering::AcqRel);
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(error) => return Err(error),
        };
        let Some(outcome) = outcome else {
            writer_busy_yields.fetch_add(1, Ordering::AcqRel);
            std::thread::sleep(Duration::from_millis(1));
            continue;
        };
        result.batches = result.batches.saturating_add(1);
        result.rows_examined = result
            .rows_examined
            .saturating_add(u64::try_from(outcome.rows_examined)?);
        result.logical_bytes_examined = result
            .logical_bytes_examined
            .saturating_add(outcome.logical_bytes_examined);
        result.removals.nodes = result
            .removals
            .nodes
            .saturating_add(u64::try_from(outcome.stats.nodes_removed)?);
        result.removals.value_versions = result
            .removals
            .value_versions
            .saturating_add(u64::try_from(outcome.stats.value_versions_removed)?);
        result.removals.key_preimages = result
            .removals
            .key_preimages
            .saturating_add(u64::try_from(outcome.stats.preimages_removed)?);
        result.removals.stale_indices = result
            .removals
            .stale_indices
            .saturating_add(u64::try_from(outcome.stats.stale_indices_removed)?);
        result.removals.roots = result
            .removals
            .roots
            .saturating_add(u64::try_from(outcome.stats.roots_removed)?);
        result.latencies.push(duration_us(outcome.elapsed));
        if outcome.complete {
            return Ok(result);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn persist_empty_collision_version(store: &ApplicationStore, state: &mut AppState) -> Result<u64> {
    let started = Instant::now();
    let delta = BlockDelta::default();
    let next_height = state.height.saturating_add(1);
    let writes = authenticated_writes_for_delta(next_height, &delta)?;
    let auth_update = store
        .plan_auth_update(next_height, writes)
        .with_context(|| format!("plan empty authenticated version {next_height}"))?;
    let pending = PendingBlock {
        height: next_height,
        app_hash: auth_update.root_hash.into(),
        tx_results: Vec::new(),
        validator_updates: Vec::new(),
        delta,
        auth_update,
    };
    store
        .persist_transition(state, &pending, 0)
        .with_context(|| format!("persist empty authenticated version {next_height}"))?;
    state.height = pending.height;
    state.app_hash = pending.app_hash;
    state.pending = None;
    Ok(elapsed_us(started))
}

fn exercise_format4_snapshot_restore(
    config: &PersistentScaleConfig,
    report: &mut PersistentScaleReport,
    source: &CometBftApplication,
    source_height: u64,
    source_app_hash: [u8; 32],
) -> Result<PersistentSnapshotReport> {
    let source_state = source
        .core
        .state
        .lock()
        .map_err(|_| anyhow::anyhow!("persistent snapshot source state lock poisoned"))?
        .clone();
    ensure!(
        (source_state.height, source_state.app_hash) == (source_height, source_app_hash),
        "persistent snapshot source head changed before capture"
    );
    let source_store = source
        .core
        .store
        .as_ref()
        .context("persistent snapshot source has no SQLite store")?;
    let snapshot_path = config.work_dir.join("source-format4.snapshot.sqlite3");
    let build_started = Instant::now();
    let pinned = source_store.pin_snapshot(&source_state)?;
    let record = build_store_snapshot(
        source_store,
        SCALE_CHAIN_ID,
        PendingDiskSnapshot {
            state: source_state,
            disk_path: snapshot_path.clone(),
            pinned,
        },
    )?;
    let build_us = elapsed_us(build_started);
    let snapshot = record.snapshot.clone();
    ensure!(
        snapshot.format == SNAPSHOT_FORMAT_V4 && snapshot.height == source_height,
        "persistent scale snapshot is not the expected format-4 head"
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&snapshot.metadata).context("decode format-4 scale metadata")?;
    let total_bytes = metadata
        .get("total_bytes")
        .and_then(serde_json::Value::as_u64)
        .context("format-4 scale metadata is missing total_bytes")?;
    ensure!(
        fs::metadata(&snapshot_path)?.len() == total_bytes,
        "format-4 scale snapshot byte length mismatch"
    );
    install_snapshot_record(
        &source.core.snapshots,
        source_height,
        record,
        RETAINED_DISK_SNAPSHOTS,
    )?;

    let target_status_path = config.work_dir.join("target.status");
    let target_database_path = database_path_for_status(&target_status_path);
    let target_config = scale_application_config(target_status_path);
    let mut target = CometBftApplication::new(target_config.clone())?;
    let offer = || RequestOfferSnapshot {
        snapshot: Some(snapshot.clone()),
        app_hash: Bytes::copy_from_slice(&source_app_hash),
    };
    ensure!(
        target.offer_snapshot(offer()).result == response_offer_snapshot::Result::Accept as i32,
        "fresh target rejected the format-4 scale snapshot"
    );
    let chunks_before_restart = if snapshot.chunks > 1 {
        (snapshot.chunks / 2).max(1).min(snapshot.chunks - 1)
    } else {
        0
    };
    let restore_started = Instant::now();
    for index in 0..chunks_before_restart {
        apply_scale_snapshot_chunk(source, &target, &snapshot, index)?;
    }
    let resumed_across_restart = chunks_before_restart > 0;
    if resumed_across_restart {
        drop(target);
        target = CometBftApplication::new(target_config.clone())?;
        ensure!(
            target.offer_snapshot(offer()).result == response_offer_snapshot::Result::Accept as i32,
            "restarted target rejected the resumable format-4 snapshot"
        );
    }
    for index in chunks_before_restart..snapshot.chunks {
        apply_scale_snapshot_chunk(source, &target, &snapshot, index)?;
    }
    let restore_us = elapsed_us(restore_started);
    let (restored_height, restored_hash) = target.height_and_app_hash()?;
    let exact_head_match = (restored_height, restored_hash) == (source_height, source_app_hash);
    ensure!(
        exact_head_match,
        "format-4 scale restore differs from the source head"
    );
    report.proofs.push(measure_proof(
        target
            .core
            .store
            .as_ref()
            .context("restored target has no SQLite store")?,
        "after_snapshot_restore_latest_membership",
        source_height,
        stored_object_key(&scale_object_id(0))?,
        true,
    )?);
    report.database_metrics.push(database_metrics(
        "after_snapshot_restore",
        &target_database_path,
    )?);

    let continuation_height = source_height.saturating_add(1);
    let finalized = target.finalize_block(RequestFinalizeBlock {
        height: i64::try_from(continuation_height)?,
        time: Some(Timestamp {
            seconds: i64::try_from(continuation_height)?,
            nanos: 0,
        }),
        ..Default::default()
    });
    ensure!(
        finalized.app_hash.len() == 32,
        "restored target continuation returned a non-32-byte AppHash"
    );
    target.commit();
    let (continued_height, continued_hash) = target.height_and_app_hash()?;
    let continued_after_restore = continued_height == continuation_height;
    ensure!(
        continued_after_restore,
        "restored target did not continue at the next height"
    );
    report.proofs.push(measure_proof(
        target
            .core
            .store
            .as_ref()
            .context("continued target has no SQLite store")?,
        "after_snapshot_restore_continuation_membership",
        continued_height,
        stored_object_key(&scale_object_id(0))?,
        true,
    )?);
    wait_for_snapshot_workers_idle(&target)?;
    drop(target);

    let restart_started = Instant::now();
    let restarted_target = CometBftApplication::new(target_config)?;
    let restart_after_continue_us = elapsed_us(restart_started);
    let restart_after_continue_match =
        restarted_target.height_and_app_hash()? == (continued_height, continued_hash);
    ensure!(
        restart_after_continue_match,
        "continued snapshot target did not survive restart"
    );
    report.database_metrics.push(database_metrics(
        "after_snapshot_target_restart",
        &target_database_path,
    )?);
    sample_file_peaks(&target_database_path, &mut report.file_peaks)?;

    Ok(PersistentSnapshotReport {
        format: snapshot.format,
        chunks: snapshot.chunks,
        total_bytes,
        build_us,
        restore_us,
        resumed_across_restart,
        chunks_before_restart,
        source_height,
        source_app_hash_hex: hex::encode(source_app_hash),
        restored_height,
        restored_app_hash_hex: hex::encode(restored_hash),
        exact_head_match,
        continued_height,
        continued_app_hash_hex: hex::encode(continued_hash),
        continued_after_restore,
        restart_after_continue_us,
        restart_after_continue_match,
    })
}

fn apply_scale_snapshot_chunk(
    source: &CometBftApplication,
    target: &CometBftApplication,
    snapshot: &Snapshot,
    index: u32,
) -> Result<()> {
    let chunk = source
        .load_snapshot_chunk(RequestLoadSnapshotChunk {
            height: snapshot.height,
            format: snapshot.format,
            chunk: index,
        })
        .chunk;
    ensure!(
        !chunk.is_empty(),
        "format-4 scale source returned an empty snapshot chunk"
    );
    let applied = target.apply_snapshot_chunk(RequestApplySnapshotChunk {
        index,
        chunk,
        sender: "persistent-scale-source".to_string(),
    });
    ensure!(
        applied.result == response_apply_snapshot_chunk::Result::Accept as i32,
        "format-4 scale target rejected snapshot chunk {index}"
    );
    Ok(())
}

fn wait_for_snapshot_workers_idle(application: &CometBftApplication) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(7_200);
    loop {
        let active = application
            .core
            .snapshot_building
            .lock()
            .map_err(|_| anyhow::anyhow!("snapshot worker state lock poisoned"))?
            .active
            .is_some();
        if !active {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "format-4 snapshot worker did not finish before the scale deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn validate_config(config: &PersistentScaleConfig) -> Result<()> {
    ensure!(config.objects > 0, "objects must be positive");
    ensure!(config.updates > 0, "updates must be positive");
    ensure!(config.batch_size > 0, "batch_size must be positive");
    ensure!(config.live_set > 0, "live_set must be positive");
    ensure!(
        config.live_set <= config.objects,
        "live_set must not exceed initial objects"
    );
    ensure!(
        config.batch_size <= config.live_set,
        "batch_size must not exceed live_set because one version cannot update a key twice"
    );
    ensure!(
        config.prune_retain_versions > 0,
        "prune retention must be positive"
    );
    ensure!(
        config.prune_batch_rows > 0,
        "prune batch row budget must be positive"
    );
    ensure!(
        config.prune_batch_logical_bytes > 0,
        "prune batch logical-byte budget must be positive"
    );
    let initial_batches = config.objects.div_ceil(config.batch_size);
    let update_batches = config.updates.div_ceil(config.batch_size);
    ensure!(
        config.prune_retain_versions <= initial_batches.saturating_add(update_batches),
        "prune retention exceeds the committed workload version count"
    );
    Ok(())
}

fn prepare_work_dir(path: &Path) -> Result<()> {
    if path.exists() {
        ensure!(
            fs::read_dir(path)?.next().transpose()?.is_none(),
            "persistent scale work directory is not empty: {}",
            path.display()
        );
    } else {
        fs::create_dir_all(path).with_context(|| {
            format!("create persistent scale work directory {}", path.display())
        })?;
    }
    Ok(())
}

fn scale_application_config(state_path: PathBuf) -> ConsensusAppConfig {
    ConsensusAppConfig {
        schema: CONFIG_SCHEMA_V1.to_string(),
        chain_id: SCALE_CHAIN_ID.to_string(),
        authorized_signers: vec![AuthorizedSignerV1 {
            signer_id: SCALE_SIGNER_ID.to_string(),
            signer_role: "operator".to_string(),
            public_key_hex: hex::encode([1_u8; 32]),
        }],
        state_path: Some(state_path),
    }
}

fn initialize_application(config: ConsensusAppConfig) -> Result<CometBftApplication> {
    let application = CometBftApplication::new(config.clone())?;
    let initial_validators = (2_u8..=5)
        .map(|seed| ConsensusValidatorV1 {
            public_key_hex: hex::encode([seed; 32]),
            voting_power: 10,
        })
        .collect::<Vec<_>>();
    let genesis = GenesisAppStateV3 {
        schema: GENESIS_SCHEMA_V3.to_string(),
        chain_id: config.chain_id.clone(),
        app_version: APP_VERSION,
        authorized_signers: config.authorized_signers,
        research_authorities: AuthoritySetV1::default(),
        validator_governance: ValidatorGovernanceV1 {
            schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_string(),
            signer_id: SCALE_SIGNER_ID.to_string(),
            min_activation_delay_blocks: 2,
            unsafe_allow_single_validator_genesis: false,
        },
        initial_validators: initial_validators.clone(),
    };
    let validators = validators_to_abci(&initial_validators)?;
    let response = application.init_chain(RequestInitChain {
        chain_id: config.chain_id,
        app_state_bytes: Bytes::from(serde_json::to_vec(&genesis)?),
        consensus_params: Some(ConsensusParams {
            version: Some(VersionParams { app: APP_VERSION }),
            ..Default::default()
        }),
        validators,
        ..Default::default()
    });
    ensure!(
        response.app_hash.len() == 32,
        "persistent scale genesis returned a non-32-byte AppHash"
    );
    Ok(application)
}

#[allow(clippy::too_many_arguments)]
fn persist_batch(
    store: &ApplicationStore,
    state: &mut AppState,
    phase: PersistentScalePhase,
    batch_index: u64,
    phase_operations_completed: u64,
    objects: Vec<StoredObject>,
    database_path: &Path,
) -> Result<PersistentBatchMetric> {
    let total_started = Instant::now();
    let operations = u64::try_from(objects.len())?;
    let mut delta = BlockDelta::default();
    for object in objects {
        ensure!(
            delta
                .objects
                .insert(object.object_key_hex.clone(), object)
                .is_none(),
            "persistent scale batch updates one key more than once"
        );
    }
    let next_height = state.height.saturating_add(1);
    let writes = authenticated_writes_for_delta(next_height, &delta)?;
    let plan_started = Instant::now();
    let auth_update = store
        .plan_auth_update(next_height, writes)
        .with_context(|| format!("plan persistent {phase:?} batch {batch_index}"))?;
    let plan_us = elapsed_us(plan_started);
    let app_hash = auth_update.root_hash.into();
    let pending = PendingBlock {
        height: next_height,
        app_hash,
        tx_results: Vec::new(),
        validator_updates: Vec::new(),
        delta,
        auth_update,
    };
    let persist_started = Instant::now();
    store
        .persist_transition(state, &pending, 0)
        .with_context(|| format!("persist {phase:?} batch {batch_index}"))?;
    let persist_us = elapsed_us(persist_started);
    state.height = pending.height;
    state.app_hash = pending.app_hash;
    state.pending = None;
    let database = file_usage(database_path)?;
    let wal = file_usage(&sqlite_sidecar(database_path, "-wal"))?;
    Ok(PersistentBatchMetric {
        phase,
        batch_index,
        version: next_height,
        operations,
        phase_operations_completed,
        plan_us,
        persist_us,
        total_us: elapsed_us(total_started),
        root_hash_hex: hex::encode(app_hash),
        database_logical_bytes: database.logical_bytes,
        wal_logical_bytes: wal.logical_bytes,
    })
}

fn scale_object(object_index: u64, update_sequence: u64, version: u64) -> StoredObject {
    ObjectMutation {
        object_key_hex: scale_object_id(object_index),
        object_type: SCALE_OBJECT_TYPE.to_string(),
        expected_version: (version > 1).then_some(version.saturating_sub(1)),
        next_version: version,
        value_bytes: scale_value(object_index, update_sequence),
    }
    .into_stored()
}

fn scale_object_id(index: u64) -> String {
    format!("persistent-scale-object-{index:016x}")
}

fn scale_value(object_index: u64, update_sequence: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(48);
    value.extend_from_slice(b"trnm-persistent-scale-v1");
    value.extend_from_slice(&object_index.to_be_bytes());
    value.extend_from_slice(&update_sequence.to_be_bytes());
    value
}

fn measure_proof(
    store: &ApplicationStore,
    stage: &str,
    version: u64,
    key: Vec<u8>,
    expected_membership: bool,
) -> Result<PersistentProofMetric> {
    let started = Instant::now();
    let proof = store
        .prove(version, key)
        .with_context(|| format!("prove persistent state at {stage} version {version}"))?;
    let elapsed_us = elapsed_us(started);
    let membership = proof.value.is_some();
    ensure!(
        membership == expected_membership,
        "persistent proof membership differs at {stage}"
    );
    Ok(PersistentProofMetric {
        stage: stage.to_string(),
        version,
        key_hex: hex::encode(&proof.key),
        membership,
        value_bytes: u64::try_from(proof.value.as_ref().map_or(0, Vec::len))?,
        proof_bytes: u64::try_from(proof.encoded_commitment_proof().len())?,
        root_hash_hex: hex::encode(<[u8; 32]>::from(proof.root_hash)),
        elapsed_us,
        verified_by_store: true,
    })
}

fn phase_latency_reports(metrics: &[PersistentBatchMetric]) -> Vec<PhaseLatencyReport> {
    [
        PersistentScalePhase::InitialLoad,
        PersistentScalePhase::Update,
    ]
    .into_iter()
    .filter_map(|phase| {
        let selected = metrics
            .iter()
            .filter(|metric| metric.phase == phase)
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return None;
        }
        let plans = selected
            .iter()
            .map(|metric| metric.plan_us)
            .collect::<Vec<_>>();
        let persists = selected
            .iter()
            .map(|metric| metric.persist_us)
            .collect::<Vec<_>>();
        let totals = selected
            .iter()
            .map(|metric| metric.total_us)
            .collect::<Vec<_>>();
        Some(PhaseLatencyReport {
            phase,
            plan: latency_stats(&plans).ok()?,
            persist: latency_stats(&persists).ok()?,
            total: latency_stats(&totals).ok()?,
        })
    })
    .collect()
}

fn latency_stats(samples: &[u64]) -> Result<PersistentLatencyStats> {
    ensure!(!samples.is_empty(), "latency sample set is empty");
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    Ok(PersistentLatencyStats {
        samples: u64::try_from(sorted.len())?,
        min_us: sorted[0],
        p50_us: nearest_rank(&sorted, 50),
        p95_us: nearest_rank(&sorted, 95),
        p99_us: nearest_rank(&sorted, 99),
        max_us: sorted[sorted.len() - 1],
    })
}

fn nearest_rank(sorted: &[u64], percentile: usize) -> u64 {
    let rank = sorted
        .len()
        .saturating_mul(percentile)
        .div_ceil(100)
        .saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)]
}

fn database_metrics(stage: &str, database_path: &Path) -> Result<DatabaseMetrics> {
    let connection = Connection::open_with_flags(
        database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("open scale database {}", database_path.display()))?;
    connection.execute_batch(
        "
        PRAGMA trusted_schema=OFF;
        PRAGMA query_only=ON;
        PRAGMA busy_timeout=5000;
        ",
    )?;
    let journal_mode =
        connection.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?;
    let synchronous = connection.query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))?;
    ensure!(
        journal_mode.eq_ignore_ascii_case("wal") && synchronous == 2,
        "persistent scale database is not WAL/FULL"
    );
    Ok(DatabaseMetrics {
        stage: stage.to_string(),
        journal_mode,
        synchronous,
        page_size: pragma_u64(&connection, "page_size")?,
        page_count: pragma_u64(&connection, "page_count")?,
        freelist_count: pragma_u64(&connection, "freelist_count")?,
        objects: table_count(&connection, "objects")?,
        auth_nodes: table_count(&connection, "auth_nodes")?,
        auth_values: table_count(&connection, "auth_values")?,
        auth_preimages: table_count(&connection, "auth_preimages")?,
        auth_stale_nodes: table_count(&connection, "auth_stale_nodes")?,
        auth_stale_values: table_count(&connection, "auth_stale_values")?,
        auth_roots: table_count(&connection, "auth_roots")?,
        database: file_usage(database_path)?,
        wal: file_usage(&sqlite_sidecar(database_path, "-wal"))?,
        shm: file_usage(&sqlite_sidecar(database_path, "-shm"))?,
    })
}

fn pragma_u64(connection: &Connection, pragma: &str) -> Result<u64> {
    let query = format!("PRAGMA {pragma}");
    Ok(connection.query_row(&query, [], |row| row.get::<_, u64>(0))?)
}

fn table_count(connection: &Connection, table: &str) -> Result<u64> {
    let query = format!("SELECT COUNT(*) FROM {table}");
    Ok(connection.query_row(&query, [], |row| row.get::<_, u64>(0))?)
}

fn sample_file_peaks(database_path: &Path, peaks: &mut PersistentFilePeaks) -> Result<()> {
    let database = file_usage(database_path)?;
    let wal = file_usage(&sqlite_sidecar(database_path, "-wal"))?;
    let shm = file_usage(&sqlite_sidecar(database_path, "-shm"))?;
    peaks.database_logical_bytes = peaks.database_logical_bytes.max(database.logical_bytes);
    peaks.database_allocated_bytes = peaks.database_allocated_bytes.max(database.allocated_bytes);
    peaks.wal_logical_bytes = peaks.wal_logical_bytes.max(wal.logical_bytes);
    peaks.wal_allocated_bytes = peaks.wal_allocated_bytes.max(wal.allocated_bytes);
    peaks.shm_logical_bytes = peaks.shm_logical_bytes.max(shm.logical_bytes);
    peaks.shm_allocated_bytes = peaks.shm_allocated_bytes.max(shm.allocated_bytes);
    Ok(())
}

fn sample_work_dir_peaks(root: &Path) -> Result<PersistentFilePeaks> {
    let mut sample = PersistentFilePeaks::default();
    sample_work_dir_entry(root, &mut sample)?;
    Ok(sample)
}

fn sample_work_dir_entry(path: &Path, sample: &mut PersistentFilePeaks) -> Result<()> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            match entry {
                Ok(entry) => sample_work_dir_entry(&entry.path(), sample)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Ok(());
    }
    let usage = file_usage(path)?;
    if !usage.exists {
        return Ok(());
    }
    sample.work_dir_logical_bytes = sample
        .work_dir_logical_bytes
        .saturating_add(usage.logical_bytes);
    sample.work_dir_allocated_bytes = sample
        .work_dir_allocated_bytes
        .saturating_add(usage.allocated_bytes);

    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let encoded_path = path.to_string_lossy();
    if name.ends_with(".sqlite3")
        && !name.contains("snapshot")
        && !encoded_path.contains(".restore")
    {
        sample.database_logical_bytes = sample
            .database_logical_bytes
            .saturating_add(usage.logical_bytes);
        sample.database_allocated_bytes = sample
            .database_allocated_bytes
            .saturating_add(usage.allocated_bytes);
    }
    if name.ends_with("-wal") {
        sample.wal_logical_bytes = sample.wal_logical_bytes.saturating_add(usage.logical_bytes);
        sample.wal_allocated_bytes = sample
            .wal_allocated_bytes
            .saturating_add(usage.allocated_bytes);
    }
    if name.ends_with("-shm") {
        sample.shm_logical_bytes = sample.shm_logical_bytes.saturating_add(usage.logical_bytes);
        sample.shm_allocated_bytes = sample
            .shm_allocated_bytes
            .saturating_add(usage.allocated_bytes);
    }
    if name.contains("snapshot") || encoded_path.contains(".snapshots/") {
        sample.snapshot_logical_bytes = sample
            .snapshot_logical_bytes
            .saturating_add(usage.logical_bytes);
        sample.snapshot_allocated_bytes = sample
            .snapshot_allocated_bytes
            .saturating_add(usage.allocated_bytes);
    }
    if encoded_path.contains(".restore/")
        || name.ends_with(".part")
        || name.ends_with(".journal.json")
    {
        sample.restore_staging_logical_bytes = sample
            .restore_staging_logical_bytes
            .saturating_add(usage.logical_bytes);
        sample.restore_staging_allocated_bytes = sample
            .restore_staging_allocated_bytes
            .saturating_add(usage.allocated_bytes);
    }
    if name.ends_with(".tmp") || name.contains(".tmp.") || name.ends_with(".part") {
        sample.temporary_logical_bytes = sample
            .temporary_logical_bytes
            .saturating_add(usage.logical_bytes);
        sample.temporary_allocated_bytes = sample
            .temporary_allocated_bytes
            .saturating_add(usage.allocated_bytes);
    }
    Ok(())
}

fn file_usage(path: &Path) -> Result<FileUsage> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileUsage::default());
        }
        Err(error) => return Err(error.into()),
    };
    #[cfg(unix)]
    let allocated_bytes = {
        use std::os::unix::fs::MetadataExt;
        metadata.blocks().saturating_mul(512)
    };
    #[cfg(not(unix))]
    let allocated_bytes = metadata.len();
    Ok(FileUsage {
        exists: true,
        logical_bytes: metadata.len(),
        allocated_bytes,
    })
}

fn database_path_for_status(status_path: &Path) -> PathBuf {
    let extension = status_path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.sqlite3"))
        .unwrap_or_else(|| "sqlite3".to_string());
    status_path.with_extension(extension)
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut encoded = path.as_os_str().to_os_string();
    encoded.push(suffix);
    PathBuf::from(encoded)
}

fn elapsed_us(started: Instant) -> u64 {
    duration_us(started.elapsed())
}

fn duration_us(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}
